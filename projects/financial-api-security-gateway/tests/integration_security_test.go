package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/audit"
	"github.com/financial-security/financial-api-security-gateway/src/domain"
	"github.com/financial-security/financial-api-security-gateway/src/gateway"
	"github.com/financial-security/financial-api-security-gateway/src/mockapi"
	"github.com/financial-security/financial-api-security-gateway/src/oidc"
	"github.com/financial-security/financial-api-security-gateway/src/pki"
	"github.com/financial-security/financial-api-security-gateway/src/policy"
	"github.com/financial-security/financial-api-security-gateway/src/ratelimit"
	"github.com/financial-security/financial-api-security-gateway/src/signing"
)

type testEnv struct {
	baseURL         string
	cfg             domain.GatewayConfig
	ca              *pki.TestCA
	rogueCA         *pki.TestCA
	readerCert      *pki.IssuedCert
	routerCert      *pki.IssuedCert
	auditorCert     *pki.IssuedCert
	keyRing         *oidc.KeyRing
	issuer          *oidc.Issuer
	jtiRevocations  *oidc.MemoryTokenRevocationStore
	certRevocations *pki.MemoryCertRevocationStore
	sigKeys         *signing.KeyStore
	readerPriv      ed25519.PrivateKey
	routerPriv      ed25519.PrivateKey
	auditorPriv     ed25519.PrivateKey
	auditSink       *audit.MemorySink
	metrics         *audit.Metrics
	clock           *domain.FixedClock
	cleanup         func()
}

func startLiveGatewayEnv(t *testing.T, timeoutMs int) *testEnv {
	t.Helper()
	cfg, ps, reg := loadTestConfig(t)
	if timeoutMs > 0 {
		cfg.UpstreamTimeoutMs = timeoutMs
	}
	clock := domain.NewFixedClock(time.Now().UTC())

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	upstreamSrv := &http.Server{Handler: mockapi.NewSimulatedFinancialAPI().Handler()}
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()
	cfg.UpstreamURL = "http://" + upstreamLn.Addr().String()

	ca, err := pki.NewTestCA("FinSec Test Root CA", clock)
	if err != nil {
		t.Fatalf("new test ca: %v", err)
	}
	rogueCA, err := pki.NewTestCA("Untrusted Rogue CA", clock)
	if err != nil {
		t.Fatalf("new rogue ca: %v", err)
	}
	serverCert, _ := ca.IssueServerCert("gateway.finsec.local", 2*time.Hour)
	readerCert, _ := ca.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 2*time.Hour)
	routerCert, _ := ca.IssueClientCert("cli-order-router", "spiffe://finsec.local/clients/cli-order-router", 2*time.Hour)
	auditorCert, _ := ca.IssueClientCert("cli-risk-auditor", "spiffe://finsec.local/clients/cli-risk-auditor", 2*time.Hour)
	certRev := pki.NewMemoryCertRevocationStore()

	kr := oidc.NewKeyRing()
	_, _ = kr.AddEd25519Key("oidc-live-k1", nil, nil, true, clock.Now())
	issuer := oidc.NewIssuer(kr)
	jtiRev := oidc.NewMemoryTokenRevocationStore()

	sigKeys := signing.NewKeyStore()
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	oPub, oPriv, _ := ed25519.GenerateKey(rand.Reader)
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	sigKeys.AddEd25519Key("sig-reader-1", "cli-ledger-reader", rPub)
	sigKeys.AddEd25519Key("sig-router-1", "cli-order-router", oPub)
	sigKeys.AddEd25519Key("sig-auditor-1", "cli-risk-auditor", aPub)

	polEngine, err := policy.NewEngine(ps, reg)
	if err != nil {
		t.Fatalf("policy engine: %v", err)
	}
	auditSink := audit.NewMemorySink()
	metrics := audit.NewMetrics()
	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, kr, jtiRev, clock),
		RequestVerifier: signing.NewRequestVerifier(cfg.Signing, sigKeys, signing.NewMemoryNonceStore(cfg.Signing.MaxNonceEntries), clock),
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: certRev,
	}
	gwHandler, err := gateway.NewServer(eval, audit.NewLogger(audit.NewRedactor(cfg.Audit.RedactHeaders, cfg.Audit.RedactJSONKeys), auditSink), metrics, clock)
	if err != nil {
		t.Fatalf("new gateway server: %v", err)
	}

	gwLn, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig(ca, serverCert, certRev))
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	gwSrv := &http.Server{Handler: gwHandler}
	go func() { _ = gwSrv.Serve(gwLn) }()

	return &testEnv{
		baseURL:         "https://" + gwLn.Addr().String(),
		cfg:             cfg,
		ca:              ca,
		rogueCA:         rogueCA,
		readerCert:      readerCert,
		routerCert:      routerCert,
		auditorCert:     auditorCert,
		keyRing:         kr,
		issuer:          issuer,
		jtiRevocations:  jtiRev,
		certRevocations: certRev,
		sigKeys:         sigKeys,
		readerPriv:      rPriv,
		routerPriv:      oPriv,
		auditorPriv:     aPriv,
		auditSink:       auditSink,
		metrics:         metrics,
		clock:           clock,
		cleanup: func() {
			_ = gwSrv.Close()
			_ = gwLn.Close()
			_ = upstreamSrv.Close()
			_ = upstreamLn.Close()
		},
	}
}

func (e *testEnv) mint(t *testing.T, sub, jti, thumb string, scopes []string) string {
	t.Helper()
	now := e.clock.Now()
	tok, err := e.issuer.MintToken(oidc.MintParams{
		Issuer: e.cfg.OIDC.Issuer, Subject: sub, Audience: e.cfg.OIDC.Audience,
		JWTID: jti, Scopes: scopes, CertThumbprint: thumb,
		IssuedAt: now, NotBefore: now.Add(-5 * time.Second), ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return tok
}

func (e *testEnv) signedRequest(t *testing.T, client *http.Client, method, path, query string, body []byte, tok, keyID, nonce string, ts time.Time, priv ed25519.PrivateKey, extraHeaders map[string]string) (*http.Response, []byte, error) {
	t.Helper()
	tsStr := ts.UTC().Format(time.RFC3339)
	sig, err := signing.SignRequest("Ed25519", keyID, tsStr, nonce, method, path, query, body, priv, nil)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	u := e.baseURL + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("X-Signature-Alg", "Ed25519")
	req.Header.Set("X-Key-ID", keyID)
	req.Header.Set("X-Request-Timestamp", tsStr)
	req.Header.Set("X-Request-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b, nil
}

func TestIntegrationValidReplayScopeEscalationRateLimitAndRedaction(t *testing.T) {
	env := startLiveGatewayEnv(t, 500)
	defer env.cleanup()

	readerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.readerCert)}}
	routerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.routerCert)}}
	auditorClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.auditorCert)}}

	readerTok := env.mint(t, "cli-ledger-reader", "jti-int-1", env.readerCert.Info.ThumbprintSHA256, []string{"accounts:read"})
	routerTok := env.mint(t, "cli-order-router", "jti-int-2", env.routerCert.Info.ThumbprintSHA256, []string{"accounts:read", "orders:write"})
	routerInsufficientTok := env.mint(t, "cli-order-router", "jti-int-3", env.routerCert.Info.ThumbprintSHA256, []string{"accounts:read"})
	auditorTok := env.mint(t, "cli-risk-auditor", "jti-int-4", env.auditorCert.Info.ThumbprintSHA256, []string{"audit:read"})

	canaryAPIKey := "CANARY_API_KEY_TOP_SECRET_12345"
	canaryCookie := "session_token=CANARY_COOKIE_VALUE_67890"

	// 1. Valid GET balance
	resp, body, err := env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-1", "nonce-int-01", env.clock.Now(), env.readerPriv, map[string]string{
		"X-Api-Key": canaryAPIKey,
		"Cookie":    canaryCookie,
	})
	if err != nil {
		t.Fatalf("valid balance request transport error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for valid balance request, got status=%d body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "SIMULATED_PAPER_ONLY") {
		t.Errorf("expected simulated paper response, got %s", string(body))
	}

	// 2. Replay attack with identical nonce must be rejected (409 ERR_NONCE_REPLAY)
	resp, body, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-1", "nonce-int-01", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("replay request error: %v", err)
	}
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), string(domain.ReasonNonceReplay)) {
		t.Fatalf("expected 409 ERR_NONCE_REPLAY, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 3. Stale request timestamp rejected (ERR_SIG_EXPIRED)
	resp, body, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, readerTok, "sig-reader-1", "nonce-stale", env.clock.Now().Add(-5*time.Minute), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("stale request error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonSigExpired)) {
		t.Fatalf("expected 401 ERR_SIG_EXPIRED, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 4. Scope escalation: reader trying POST /v1/orders -> 403 ERR_ROLE_FORBIDDEN
	orderPayload := []byte(`{"account_id":"ACC-1001","symbol":"SIM-GOOG","side":"BUY","qty":3,"limit_price":180.5}`)
	resp, body, err = env.signedRequest(t, readerClient, "POST", "/v1/orders", "", orderPayload, readerTok, "sig-reader-1", "nonce-esc-1", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("role escalation request error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), string(domain.ReasonRoleForbidden)) {
		t.Fatalf("expected 403 ERR_ROLE_FORBIDDEN, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 5. Scope escalation: order-router with missing orders:write scope -> 403 ERR_SCOPE_INSUFFICIENT
	resp, body, err = env.signedRequest(t, routerClient, "POST", "/v1/orders", "", orderPayload, routerInsufficientTok, "sig-router-1", "nonce-esc-2", env.clock.Now(), env.routerPriv, nil)
	if err != nil {
		t.Fatalf("scope escalation request error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), string(domain.ReasonScopeInsufficient)) {
		t.Fatalf("expected 403 ERR_SCOPE_INSUFFICIENT, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 6. Token theft / cert-binding mismatch: router presenting reader's JWT over router's mTLS cert -> 401 ERR_CERT_TOKEN_MISMATCH
	resp, body, err = env.signedRequest(t, routerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, readerTok, "sig-router-1", "nonce-theft-1", env.clock.Now(), env.routerPriv, nil)
	if err != nil {
		t.Fatalf("cert mismatch request error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonCertTokenMismatch)) {
		t.Fatalf("expected 401 ERR_CERT_TOKEN_MISMATCH, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 7. Valid POST order
	resp, body, err = env.signedRequest(t, routerClient, "POST", "/v1/orders", "", orderPayload, routerTok, "sig-router-1", "nonce-ord-1", env.clock.Now(), env.routerPriv, nil)
	if err != nil {
		t.Fatalf("valid order request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ACCEPTED_PAPER") {
		t.Fatalf("expected 200 ACCEPTED_PAPER, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 8. Per-resource rate limiting on /v1/audit/export (burst=5, rps=5)
	for i := 0; i < 5; i++ {
		resp, body, err = env.signedRequest(t, auditorClient, "GET", "/v1/audit/export", "", nil, auditorTok, "sig-auditor-1", "nonce-rl-"+string(rune('a'+i)), env.clock.Now(), env.auditorPriv, nil)
		if err != nil {
			t.Fatalf("rate-limit burst request %d transport error: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rate-limit burst request %d failed: status=%d body=%s", i, resp.StatusCode, string(body))
		}
	}
	// 6th immediate request must hit 429 ERR_RATE_LIMITED
	resp, body, err = env.signedRequest(t, auditorClient, "GET", "/v1/audit/export", "", nil, auditorTok, "sig-auditor-1", "nonce-rl-overflow", env.clock.Now(), env.auditorPriv, nil)
	if err != nil {
		t.Fatalf("rate-limit overflow request error: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), string(domain.ReasonRateLimited)) {
		t.Fatalf("expected 429 ERR_RATE_LIMITED, got status=%d body=%s", resp.StatusCode, string(body))
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}

	// Advance clock by 1 second -> token bucket refills and allows request again
	env.clock.Advance(1 * time.Second)
	resp, _, err = env.signedRequest(t, auditorClient, "GET", "/v1/audit/export", "", nil, auditorTok, "sig-auditor-1", "nonce-rl-recovered", env.clock.Now(), env.auditorPriv, nil)
	if err != nil {
		t.Fatalf("rate-limit refill request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after rate-limit refill, got status=%d", resp.StatusCode)
	}

	// 9. Verify mTLS rejects clients without cert, with expired cert, wrong EKU, or rogue CA cert
	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, nil)}}
	if _, err := noCertClient.Get(env.baseURL + "/v1/accounts/ACC-1001/balance"); err == nil {
		t.Errorf("expected TLS handshake failure when client presents no mTLS certificate")
	}
	rogueCert, _ := env.rogueCA.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 1*time.Hour)
	rogueClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, rogueCert)}}
	if _, err := rogueClient.Get(env.baseURL + "/v1/accounts/ACC-1001/balance"); err == nil {
		t.Errorf("expected TLS handshake failure for untrusted rogue CA client certificate")
	}
	expiredCert, _ := env.ca.IssueExpiredClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader")
	expiredClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, expiredCert)}}
	if _, err := expiredClient.Get(env.baseURL + "/v1/accounts/ACC-1001/balance"); err == nil {
		t.Errorf("expected TLS handshake failure for expired client certificate")
	}
	wrongEKUCert, _ := env.ca.IssueWrongEKUClientCert("cli-ledger-reader")
	wrongEKUClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, wrongEKUCert)}}
	if _, err := wrongEKUClient.Get(env.baseURL + "/v1/accounts/ACC-1001/balance"); err == nil {
		t.Errorf("expected TLS handshake failure for wrong-EKU client certificate")
	}

	// 10. Strict audit log secret-redaction verification across every emitted event
	events := env.auditSink.Events()
	if len(events) == 0 {
		t.Fatalf("expected audit events to be recorded")
	}
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		s := string(raw)
		for _, forbidden := range []string{canaryAPIKey, canaryCookie, readerTok, routerTok, auditorTok, "eyJ"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("SECRET LEAK in audit event %s: found %q", ev.EventID, forbidden)
			}
		}
	}
}
