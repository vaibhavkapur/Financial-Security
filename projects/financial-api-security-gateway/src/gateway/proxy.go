package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/audit"
	"github.com/financial-security/financial-api-security-gateway/src/domain"
	"github.com/financial-security/financial-api-security-gateway/src/pki"
)

// Server is the HTTP/mTLS enforcement boundary and reverse proxy.
type Server struct {
	Evaluator *Evaluator
	Audit     *audit.Logger
	Metrics   *audit.Metrics
	Clock     domain.Clock
	proxy     *httputil.ReverseProxy
	reqSeq    atomic.Uint64
}

func NewServer(eval *Evaluator, auditLog *audit.Logger, metrics *audit.Metrics, clock domain.Clock) (*Server, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}
	if metrics == nil {
		metrics = audit.NewMetrics()
	}
	if auditLog == nil {
		auditLog = audit.NewLogger(
			audit.NewRedactor(eval.Config.Audit.RedactHeaders, eval.Config.Audit.RedactJSONKeys),
			audit.NewMemorySink(),
		)
	}
	target, err := url.Parse(eval.Config.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream url: %w", err)
	}

	s := &Server{
		Evaluator: eval,
		Audit:     auditLog,
		Metrics:   metrics,
		Clock:     clock,
	}

	timeout := time.Duration(eval.Config.UpstreamTimeoutMs) * time.Millisecond
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		IdleConnTimeout:       60 * time.Second,
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Strip client authentication & signing material before forwarding upstream.
		req.Header.Del("Authorization")
		req.Header.Del("X-Signature")
		req.Header.Del("X-Api-Key")
		req.Header.Del("Cookie")
	}

	s.proxy = proxy
	return s, nil
}

// ServeHTTP enforces all security boundaries, proxies authorized requests with strict timeout, and logs redacted audit events.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if reqID == "" {
		reqID = fmt.Sprintf("req-%06d", s.reqSeq.Add(1))
	}
	w.Header().Set("X-Request-ID", reqID)

	// Read bounded body (+1 byte to detect oversized payloads cleanly).
	maxBytes := s.Evaluator.Config.Audit.MaxBodyBytes
	limited := io.LimitReader(r.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	_ = r.Body.Close()
	if err != nil {
		s.writeDenied(w, r, reqID, domain.EvaluationResult{
			RequestID:  reqID,
			Decision:   domain.DecisionDeny,
			ReasonCode: domain.ReasonBodyTooLarge,
			HTTPStatus: http.StatusBadRequest,
			Message:    "failed to read request body",
		}, domain.PeerCertInfo{}, start)
		return
	}

	// Extract verified mTLS peer cert if TLS is active.
	var peerCert domain.PeerCertInfo
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peerCert = pki.ExtractPeerCertInfo(r.TLS.PeerCertificates[0])
	}

	bearer := ""
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authHdr) > 7 && strings.EqualFold(authHdr[:7], "Bearer ") {
		bearer = strings.TrimSpace(authHdr[7:])
	}

	env := domain.RequestEnvelope{
		RequestID:  reqID,
		Method:     r.Method,
		Path:       r.URL.Path,
		RawQuery:   r.URL.RawQuery,
		Headers:    r.Header.Clone(),
		Body:       body,
		BearerAuth: bearer,
		PeerCert:   peerCert,
		Signature: domain.SignatureHeaders{
			Algorithm: r.Header.Get("X-Signature-Alg"),
			KeyID:     r.Header.Get("X-Key-ID"),
			Timestamp: r.Header.Get("X-Request-Timestamp"),
			Nonce:     r.Header.Get("X-Request-Nonce"),
			Signature: r.Header.Get("X-Signature"),
		},
		ReceivedAt: s.Clock.Now().UTC(),
	}

	evalRes := s.Evaluator.Evaluate(env)
	if evalRes.Decision != domain.DecisionAllow {
		s.writeDenied(w, r, reqID, evalRes, peerCert, start)
		return
	}

	// Forward verified identity context headers to the simulated upstream API.
	timeout := time.Duration(s.Evaluator.Config.UpstreamTimeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	outReq := r.Clone(ctx)
	outReq.Body = io.NopCloser(bytes.NewReader(body))
	outReq.ContentLength = int64(len(body))
	outReq.Header.Set("X-Request-ID", reqID)
	outReq.Header.Set("X-Gateway-Verified-Client", evalRes.ClientID)
	outReq.Header.Set("X-Gateway-Verified-Role", evalRes.ClientRole)
	outReq.Header.Set("X-Gateway-Verified-Scopes", strings.Join(evalRes.GrantedScopes, " "))
	outReq.Header.Set("X-Gateway-Policy-Rule", evalRes.PolicyRuleID)

	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(evalRes.RateLimitRem))

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	var proxyErr error
	proxyCopy := *s.proxy
	proxyCopy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		proxyErr = err
	}
	proxyCopy.ServeHTTP(rec, outReq)

	if proxyErr != nil {
		reason := domain.ReasonUpstreamUnavailable
		status := http.StatusBadGateway
		msg := "upstream financial API unavailable"
		if errors.Is(proxyErr, context.DeadlineExceeded) || isTimeoutErr(proxyErr) {
			reason = domain.ReasonUpstreamTimeout
			status = http.StatusGatewayTimeout
			msg = fmt.Sprintf("upstream financial API timed out after %dms", s.Evaluator.Config.UpstreamTimeoutMs)
		}
		s.writeErrorJSON(w, reqID, reason, status, msg)
		s.Metrics.Record(domain.DecisionDeny, reason)
		_, _ = s.Audit.Log(domain.AuditEvent{
			Timestamp:      s.Clock.Now().UTC().Format(time.RFC3339Nano),
			RequestID:      reqID,
			ClientID:       evalRes.ClientID,
			ClientRole:     evalRes.ClientRole,
			CertThumbprint: peerCert.ThumbprintSHA256,
			CertSerialHex:  peerCert.SerialHex,
			TokenJTI:       evalRes.TokenJTI,
			Method:         r.Method,
			Path:           r.URL.Path,
			PolicyRuleID:   evalRes.PolicyRuleID,
			Decision:       domain.DecisionDeny,
			ReasonCode:     reason,
			HTTPStatus:     status,
			LatencyUs:      time.Since(start).Microseconds(),
			Message:        msg,
		}, r.Header)
		return
	}

	s.Metrics.Record(domain.DecisionAllow, domain.ReasonAllowed)
	_, _ = s.Audit.Log(domain.AuditEvent{
		Timestamp:      s.Clock.Now().UTC().Format(time.RFC3339Nano),
		RequestID:      reqID,
		ClientID:       evalRes.ClientID,
		ClientRole:     evalRes.ClientRole,
		CertThumbprint: peerCert.ThumbprintSHA256,
		CertSerialHex:  peerCert.SerialHex,
		TokenJTI:       evalRes.TokenJTI,
		Method:         r.Method,
		Path:           r.URL.Path,
		PolicyRuleID:   evalRes.PolicyRuleID,
		Decision:       domain.DecisionAllow,
		ReasonCode:     domain.ReasonAllowed,
		HTTPStatus:     rec.status,
		LatencyUs:      time.Since(start).Microseconds(),
		Message:        "proxied to upstream",
	}, r.Header)
}

func (s *Server) writeDenied(w http.ResponseWriter, r *http.Request, reqID string, evalRes domain.EvaluationResult, peerCert domain.PeerCertInfo, start time.Time) {
	if evalRes.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(evalRes.RetryAfterSeconds))
	}
	s.writeErrorJSON(w, reqID, evalRes.ReasonCode, evalRes.HTTPStatus, evalRes.Message)
	s.Metrics.Record(domain.DecisionDeny, evalRes.ReasonCode)
	_, _ = s.Audit.Log(domain.AuditEvent{
		Timestamp:      s.Clock.Now().UTC().Format(time.RFC3339Nano),
		RequestID:      reqID,
		ClientID:       evalRes.ClientID,
		ClientRole:     evalRes.ClientRole,
		CertThumbprint: peerCert.ThumbprintSHA256,
		CertSerialHex:  peerCert.SerialHex,
		TokenJTI:       evalRes.TokenJTI,
		Method:         r.Method,
		Path:           r.URL.Path,
		PolicyRuleID:   evalRes.PolicyRuleID,
		Decision:       domain.DecisionDeny,
		ReasonCode:     evalRes.ReasonCode,
		HTTPStatus:     evalRes.HTTPStatus,
		LatencyUs:      time.Since(start).Microseconds(),
		Message:        evalRes.Message,
	}, r.Header)
}

func (s *Server) writeErrorJSON(w http.ResponseWriter, reqID string, code domain.ReasonCode, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(domain.ErrorResponse{
		SchemaVersion: domain.SchemaVersion,
		RequestID:     reqID,
		ErrorCode:     code,
		Message:       msg,
		Timestamp:     s.Clock.Now().UTC().Format(time.RFC3339),
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout") ||
		strings.Contains(strings.ToLower(err.Error()), "deadline exceeded")
}
