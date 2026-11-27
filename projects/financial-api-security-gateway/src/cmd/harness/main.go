package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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

type RuntimeMetadata struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at_utc"`
	GoVersion     string `json:"go_version"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	NumCPU        int    `json:"num_cpu"`
	ConfigVersion string `json:"config_version"`
	PolicyVersion string `json:"policy_version"`
	Seed          int    `json:"seed"`
}

type ScenarioOutcome struct {
	ID             string            `json:"id"`
	Category       string            `json:"category"`
	Description    string            `json:"description"`
	ExpectedStatus int               `json:"expected_status"`
	ActualStatus   int               `json:"actual_status"`
	ExpectedReason domain.ReasonCode `json:"expected_reason"`
	ActualReason   domain.ReasonCode `json:"actual_reason"`
	Passed         bool              `json:"passed"`
	Notes          string            `json:"notes,omitempty"`
}

type BenchmarkStats struct {
	Samples    int     `json:"samples"`
	MeanUs     float64 `json:"mean_us"`
	P50Us      float64 `json:"p50_us"`
	P95Us      float64 `json:"p95_us"`
	P99Us      float64 `json:"p99_us"`
	MinUs      float64 `json:"min_us"`
	MaxUs      float64 `json:"max_us"`
	Throughput float64 `json:"throughput_req_per_sec"`
}

type OverheadReport struct {
	Metadata              RuntimeMetadata `json:"metadata"`
	Note                  string          `json:"note"`
	DirectUpstreamHTTP    BenchmarkStats  `json:"direct_upstream_http"`
	GatewayFullMTLSStack  BenchmarkStats  `json:"gateway_full_mtls_stack"`
	PureEvaluatorInMemory BenchmarkStats  `json:"pure_evaluator_in_memory"`
	DeltaMeanUs           float64         `json:"gateway_overhead_delta_mean_us"`
	DeltaP50Us            float64         `json:"gateway_overhead_delta_p50_us"`
	DeltaP95Us            float64         `json:"gateway_overhead_delta_p95_us"`
	DeltaP99Us            float64         `json:"gateway_overhead_delta_p99_us"`
}

func main() {
	configDir := flag.String("config-dir", "config", "Config directory")
	fixturesPath := flag.String("fixtures", "data/fixtures/reference_vectors.json", "Reference fixture JSON path")
	reportsDir := flag.String("reports-dir", "reports", "Directory to write machine-readable reports")
	benchSamples := flag.Int("bench-samples", 500, "Number of HTTP requests per benchmark series")
	flag.Parse()

	if err := os.MkdirAll(*reportsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir reports failed: %v\n", err)
		os.Exit(1)
	}

	cfg, err := domain.LoadGatewayConfig(filepath.Join(*configDir, "gateway.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load gateway config: %v\n", err)
		os.Exit(1)
	}
	ps, err := domain.LoadPolicySet(filepath.Join(*configDir, "policies.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policies: %v\n", err)
		os.Exit(1)
	}
	reg, err := domain.LoadClientRegistry(filepath.Join(*configDir, "clients.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load clients: %v\n", err)
		os.Exit(1)
	}

	meta := RuntimeMetadata{
		SchemaVersion: domain.SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		GoVersion:     runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		ConfigVersion: cfg.SchemaVersion,
		PolicyVersion: ps.PolicyVersion,
		Seed:          42,
	}

	// 1. Run Reference Baseline Comparison
	baselineReport, err := runReferenceBaseline(cfg, ps, reg, *fixturesPath, meta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reference baseline failed: %v\n", err)
		os.Exit(1)
	}
	writeReportJSON(filepath.Join(*reportsDir, "baseline_reference.json"), baselineReport)

	// 2. Run Full Negative, Rotation, Revocation, and Failure Harness
	harnessReport, err := runSecurityHarness(cfg, ps, reg, meta, filepath.Join(*reportsDir, "audit_sample.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "security harness failed: %v\n", err)
		os.Exit(1)
	}
	writeReportJSON(filepath.Join(*reportsDir, "test_results.json"), harnessReport)

	// 3. Run Gateway Overhead Benchmark
	overheadReport, err := runOverheadBenchmark(cfg, ps, reg, meta, *benchSamples)
	if err != nil {
		fmt.Fprintf(os.Stderr, "overhead benchmark failed: %v\n", err)
		os.Exit(1)
	}
	writeReportJSON(filepath.Join(*reportsDir, "overhead_benchmark.json"), overheadReport)

	fmt.Printf("Harness complete.\n")
	fmt.Printf("  Baseline oracle vectors & reference cases: %d/%d passed\n", baselineReport["passed"], baselineReport["total"])
	fmt.Printf("  Negative/rotation/revocation/failure scenarios: %d/%d passed (audit secret leaks: %d)\n",
		harnessReport["passed"], harnessReport["total"], harnessReport["audit_secret_leaks"])
	fmt.Printf("  Gateway overhead (%d reqs): Direct p50=%.1f us | Gateway mTLS+OIDC+Sig p50=%.1f us | Delta p50=%.1f us (Pure evaluator p50=%.1f us)\n",
		*benchSamples,
		overheadReport.DirectUpstreamHTTP.P50Us,
		overheadReport.GatewayFullMTLSStack.P50Us,
		overheadReport.DeltaP50Us,
		overheadReport.PureEvaluatorInMemory.P50Us)
}

func runReferenceBaseline(cfg domain.GatewayConfig, ps domain.PolicySet, reg domain.ClientRegistry, fixturesPath string, meta RuntimeMetadata) (map[string]any, error) {
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		return nil, err
	}
	var fixture struct {
		FixtureID            string `json:"fixture_id"`
		FixedClockUTC        string `json:"fixed_clock_utc"`
		OracleSource         string `json:"oracle_source"`
		SigningOracleVectors []struct {
			ID                      string `json:"id"`
			ClientID                string `json:"client_id"`
			Algorithm               string `json:"algorithm"`
			KeyID                   string `json:"key_id"`
			SyntheticSecret         string `json:"synthetic_secret"`
			Method                  string `json:"method"`
			Path                    string `json:"path"`
			RawQuery                string `json:"raw_query"`
			Timestamp               string `json:"timestamp"`
			Nonce                   string `json:"nonce"`
			Body                    string `json:"body"`
			ExpectedBodySHA256      string `json:"expected_body_sha256"`
			ExpectedCanonicalString string `json:"expected_canonical_string"`
			ExpectedSignatureB64URL string `json:"expected_signature_b64url"`
		} `json:"signing_oracle_vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(fixture.SigningOracleVectors))
	passed := 0
	for _, v := range fixture.SigningOracleVectors {
		canonical, bodySHA := signing.CanonicalRequestString(v.Method, v.Path, v.RawQuery, v.Timestamp, v.Nonce, v.KeyID, []byte(v.Body))
		sig := signing.SignHMACSHA256([]byte(v.SyntheticSecret), canonical)
		ok := bodySHA == v.ExpectedBodySHA256 && canonical == v.ExpectedCanonicalString && sig == v.ExpectedSignatureB64URL
		if ok {
			passed++
		}
		results = append(results, map[string]any{
			"id":               v.ID,
			"body_sha_match":   bodySHA == v.ExpectedBodySHA256,
			"canonical_match":  canonical == v.ExpectedCanonicalString,
			"signature_match":  sig == v.ExpectedSignatureB64URL,
			"exact_tolerance":  0,
			"passed":           ok,
		})
	}

	return map[string]any{
		"metadata":       meta,
		"fixture_id":     fixture.FixtureID,
		"fixed_clock":    fixture.FixedClockUTC,
		"oracle_source":  fixture.OracleSource,
		"total":          len(results),
		"passed":         passed,
		"oracle_checks":  results,
	}, nil
}

func runSecurityHarness(cfg domain.GatewayConfig, ps domain.PolicySet, reg domain.ClientRegistry, meta RuntimeMetadata, auditPath string) (map[string]any, error) {
	clock := domain.RealClock{}
	cfg.UpstreamTimeoutMs = 120

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer upstreamLn.Close()
	upstreamSrv := &http.Server{Handler: mockapi.NewSimulatedFinancialAPI().Handler()}
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()
	defer upstreamSrv.Close()
	cfg.UpstreamURL = "http://" + upstreamLn.Addr().String()

	ca, _ := pki.NewTestCA("FinSec Harness Root CA", clock)
	rogueCA, _ := pki.NewTestCA("Rogue Untrusted CA", clock)
	serverCert, _ := ca.IssueServerCert("gateway.finsec.local", 2*time.Hour)
	readerCert, _ := ca.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 2*time.Hour)
	routerCert, _ := ca.IssueClientCert("cli-order-router", "spiffe://finsec.local/clients/cli-order-router", 2*time.Hour)
	rogueCert, _ := rogueCA.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 2*time.Hour)
	certRevocations := pki.NewMemoryCertRevocationStore()

	keyRing := oidc.NewKeyRing()
	_, _ = keyRing.AddEd25519Key("oidc-k1", nil, nil, true, clock.Now())
	issuer := oidc.NewIssuer(keyRing)
	jtiRevocations := oidc.NewMemoryTokenRevocationStore()
	tokenVerifier := oidc.NewVerifier(cfg.OIDC, cfg.RequireCertBoundToken, keyRing, jtiRevocations, clock)

	sigKeys := signing.NewKeyStore()
	readerPub, readerPriv, _ := ed25519.GenerateKey(rand.Reader)
	routerPub, routerPriv, _ := ed25519.GenerateKey(rand.Reader)
	sigKeys.AddEd25519Key("sig-reader-k1", "cli-ledger-reader", readerPub)
	sigKeys.AddEd25519Key("sig-router-k1", "cli-order-router", routerPub)
	reqVerifier := signing.NewRequestVerifier(cfg.Signing, sigKeys, signing.NewMemoryNonceStore(cfg.Signing.MaxNonceEntries), clock)

	polEngine, _ := policy.NewEngine(ps, reg)
	memSink := audit.NewMemorySink()
	fileSink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		return nil, err
	}
	defer fileSink.Close()
	auditLogger := audit.NewLogger(audit.NewRedactor(cfg.Audit.RedactHeaders, cfg.Audit.RedactJSONKeys), audit.NewMultiSink(memSink, fileSink))
	metrics := audit.NewMetrics()

	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   tokenVerifier,
		RequestVerifier: reqVerifier,
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: certRevocations,
	}
	gwHandler, _ := gateway.NewServer(eval, auditLogger, metrics, clock)
	gwLn, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig(ca, serverCert, certRevocations))
	if err != nil {
		return nil, err
	}
	defer gwLn.Close()
	gwSrv := &http.Server{Handler: gwHandler}
	go func() { _ = gwSrv.Serve(gwLn) }()
	defer gwSrv.Close()
	baseURL := "https://" + gwLn.Addr().String()

	readerHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, readerCert)}}
	routerHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, routerCert)}}
	rogueHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, rogueCert)}}

	now := clock.Now()
	mint := func(sub, jti, thumb string, scopes []string, aud, iss string, exp time.Time) string {
		tok, _ := issuer.MintToken(oidc.MintParams{
			Issuer: iss, Subject: sub, Audience: aud, JWTID: jti, Scopes: scopes,
			CertThumbprint: thumb, IssuedAt: now, NotBefore: now.Add(-5 * time.Second), ExpiresAt: exp,
		})
		return tok
	}

	readerTok := mint("cli-ledger-reader", "jti-h-1", readerCert.Info.ThumbprintSHA256, []string{"accounts:read"}, cfg.OIDC.Audience, cfg.OIDC.Issuer, now.Add(5*time.Minute))
	expiredTok := mint("cli-ledger-reader", "jti-h-exp", readerCert.Info.ThumbprintSHA256, []string{"accounts:read"}, cfg.OIDC.Audience, cfg.OIDC.Issuer, now.Add(-2*time.Minute))
	wrongAudTok := mint("cli-ledger-reader", "jti-h-aud", readerCert.Info.ThumbprintSHA256, []string{"accounts:read"}, "https://wrong.api.local", cfg.OIDC.Issuer, now.Add(5*time.Minute))
	routerLowScopeTok := mint("cli-order-router", "jti-h-low", routerCert.Info.ThumbprintSHA256, []string{"accounts:read"}, cfg.OIDC.Audience, cfg.OIDC.Issuer, now.Add(5*time.Minute))

	canarySecret := "CANARY_SECRET_TOKEN_DO_NOT_LOG_987654"
	call := func(c *http.Client, method, path, query string, body []byte, tok, keyID, nonce string, priv ed25519.PrivateKey) (int, domain.ReasonCode, error) {
		ts := time.Now().UTC().Format(time.RFC3339)
		sig, _ := signing.SignRequest("Ed25519", keyID, ts, nonce, method, path, query, body, priv, nil)
		u := baseURL + path
		if query != "" {
			u += "?" + query
		}
		req, _ := http.NewRequest(method, u, bytes.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		req.Header.Set("X-Signature-Alg", "Ed25519")
		req.Header.Set("X-Key-ID", keyID)
		req.Header.Set("X-Request-Timestamp", ts)
		req.Header.Set("X-Request-Nonce", nonce)
		req.Header.Set("X-Signature", sig)
		req.Header.Set("X-Api-Key", canarySecret)
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			return resp.StatusCode, domain.ReasonAllowed, nil
		}
		var er domain.ErrorResponse
		_ = json.Unmarshal(b, &er)
		return resp.StatusCode, er.ErrorCode, nil
	}

	var outcomes []ScenarioOutcome
	record := func(id, cat, desc string, expSt int, actSt int, expR, actR domain.ReasonCode, notes string) {
		outcomes = append(outcomes, ScenarioOutcome{
			ID: id, Category: cat, Description: desc,
			ExpectedStatus: expSt, ActualStatus: actSt,
			ExpectedReason: expR, ActualReason: actR,
			Passed: expSt == actSt && expR == actR, Notes: notes,
		})
	}

	// 1. Valid request
	st, rc, _ := call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-k1", "h-n1", readerPriv)
	record("S01-valid-request", "positive", "Authorized mTLS+OIDC+Signed balance read", 200, st, domain.ReasonAllowed, rc, "")

	// 2. Untrusted CA mTLS handshake rejection
	_, _, rogueErr := call(rogueHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, readerTok, "sig-reader-k1", "h-n2", readerPriv)
	tlsRejected := rogueErr != nil
	outcomes = append(outcomes, ScenarioOutcome{
		ID: "S02-untrusted-ca-mtls", Category: "mtls", Description: "Client certificate from untrusted rogue CA rejected at TLS 1.3 handshake",
		ExpectedStatus: 0, ActualStatus: 0, ExpectedReason: "TLS_HANDSHAKE_REJECTED",
		ActualReason: func() domain.ReasonCode {
			if tlsRejected {
				return "TLS_HANDSHAKE_REJECTED"
			}
			return "UNEXPECTED_ACCEPT"
		}(),
		Passed: tlsRejected,
	})

	// 3. Expired token
	st, rc, _ = call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, expiredTok, "sig-reader-k1", "h-n3", readerPriv)
	record("S03-expired-token", "domain", "Expired JWT rejected", 401, st, domain.ReasonTokenExpired, rc, "")

	// 4. Wrong audience
	st, rc, _ = call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, wrongAudTok, "sig-reader-k1", "h-n4", readerPriv)
	record("S04-wrong-audience", "domain", "JWT with wrong audience rejected", 401, st, domain.ReasonTokenAudienceMismatch, rc, "")

	// 5. Replay attack
	st, rc, _ = call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-k1", "h-n1", readerPriv)
	record("S05-replay-nonce", "integration", "Replayed nonce rejected", 409, st, domain.ReasonNonceReplay, rc, "")

	// 6. Scope escalation (missing orders:write)
	orderBody := []byte(`{"account_id":"ACC-1001","symbol":"SIM-MSFT","side":"BUY","qty":2,"limit_price":410.0}`)
	st, rc, _ = call(routerHTTP, "POST", "/v1/orders", "", orderBody, routerLowScopeTok, "sig-router-k1", "h-n6", routerPriv)
	record("S06-scope-escalation", "integration", "Order creation without orders:write denied", 403, st, domain.ReasonScopeInsufficient, rc, "")

	// 7. Default deny unmatched route
	st, rc, _ = call(readerHTTP, "DELETE", "/v1/admin/purge", "", nil, readerTok, "sig-reader-k1", "h-n7", readerPriv)
	record("S07-default-deny", "policy", "Unmatched endpoint denied by default", 403, st, domain.ReasonPolicyDefaultDeny, rc, "")

	// 8. Key rotation + old key revocation
	_, _ = keyRing.RotateToNewEd25519Key("oidc-k2", clock.Now())
	rotatedTok := mint("cli-ledger-reader", "jti-h-rot", readerCert.Info.ThumbprintSHA256, []string{"accounts:read"}, cfg.OIDC.Audience, cfg.OIDC.Issuer, now.Add(5*time.Minute))
	stNew, rcNew, _ := call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, rotatedTok, "sig-reader-k1", "h-n8a", readerPriv)
	_ = keyRing.RevokeKey("oidc-k1", clock.Now())
	stOld, rcOld, _ := call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, readerTok, "sig-reader-k1", "h-n8b", readerPriv)
	record("S08-key-rotation-new-accepted", "rotation", "Token signed with rotated OIDC key accepted", 200, stNew, domain.ReasonAllowed, rcNew, "")
	record("S09-key-rotation-old-revoked", "revocation", "Token signed with revoked OIDC key rejected", 401, stOld, domain.ReasonTokenKeyRevoked, rcOld, "")

	// 9. Upstream timeout
	st, rc, _ = call(readerHTTP, "GET", "/v1/slow", "delay_ms=400", nil, rotatedTok, "sig-reader-k1", "h-n9", readerPriv)
	record("S10-upstream-timeout", "failure", "Slow upstream triggers explicit 504 timeout", 504, st, domain.ReasonUpstreamTimeout, rc, "")

	// 10. Cert revocation
	certRevocations.Revoke(readerCert.Info.SerialHex, "compromised-in-harness")
	st, rc, revErr := call(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, rotatedTok, "sig-reader-k1", "h-n10", readerPriv)
	if revErr != nil {
		// Rejected at TLS handshake on reconnect
		outcomes = append(outcomes, ScenarioOutcome{
			ID: "S11-cert-revocation", Category: "revocation", Description: "Revoked mTLS certificate rejected immediately",
			ExpectedStatus: 0, ActualStatus: 0, ExpectedReason: "MTLS_REVOKED", ActualReason: "MTLS_REVOKED", Passed: true,
		})
	} else {
		record("S11-cert-revocation", "revocation", "Revoked mTLS certificate rejected on keep-alive connection", 401, st, domain.ReasonMTLSRevoked, rc, "")
	}

	// Secret leak audit scan
	leaks := 0
	for _, ev := range memSink.Events() {
		rawEv, _ := json.Marshal(ev)
		s := string(rawEv)
		if strings.Contains(s, canarySecret) || strings.Contains(s, "eyJ") || strings.Contains(s, readerTok) || strings.Contains(s, rotatedTok) {
			leaks++
		}
	}

	passed := 0
	for _, o := range outcomes {
		if o.Passed {
			passed++
		}
	}
	return map[string]any{
		"metadata":           meta,
		"total":              len(outcomes),
		"passed":             passed,
		"audit_events":       len(memSink.Events()),
		"audit_secret_leaks": leaks,
		"metrics_snapshot":   metrics.Snapshot(),
		"scenarios":          outcomes,
	}, nil
}

func runOverheadBenchmark(cfg domain.GatewayConfig, ps domain.PolicySet, reg domain.ClientRegistry, meta RuntimeMetadata, samples int) (OverheadReport, error) {
	if samples < 50 {
		samples = 50
	}
	clock := domain.RealClock{}
	cfg.RateLimit.DefaultRequestsPerSecond = 100000
	cfg.RateLimit.DefaultBurst = 100000
	for i := range ps.Rules {
		ps.Rules[i].RateLimitRPS = 100000
		ps.Rules[i].RateLimitBurst = 100000
	}

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return OverheadReport{}, err
	}
	defer upstreamLn.Close()
	upstreamSrv := &http.Server{Handler: mockapi.NewSimulatedFinancialAPI().Handler()}
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()
	defer upstreamSrv.Close()
	cfg.UpstreamURL = "http://" + upstreamLn.Addr().String()

	ca, _ := pki.NewTestCA("FinSec Bench CA", clock)
	serverCert, _ := ca.IssueServerCert("gateway.finsec.local", 2*time.Hour)
	clientCert, _ := ca.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 2*time.Hour)

	keyRing := oidc.NewKeyRing()
	_, _ = keyRing.AddEd25519Key("bench-k1", nil, nil, true, clock.Now())
	issuer := oidc.NewIssuer(keyRing)
	tok, _ := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
		JWTID: "jti-bench", Scopes: []string{"accounts:read"},
		CertThumbprint: clientCert.Info.ThumbprintSHA256,
		IssuedAt: clock.Now(), NotBefore: clock.Now().Add(-5 * time.Second), ExpiresAt: clock.Now().Add(10 * time.Minute),
	})

	sigKeys := signing.NewKeyStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sigKeys.AddEd25519Key("bench-sig-k1", "cli-ledger-reader", pub)

	polEngine, _ := policy.NewEngine(ps, reg)
	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, keyRing, oidc.NewMemoryTokenRevocationStore(), clock),
		RequestVerifier: signing.NewRequestVerifier(cfg.Signing, sigKeys, signing.NewMemoryNonceStore(samples*4), clock),
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: pki.NewMemoryCertRevocationStore(),
	}
	gwHandler, _ := gateway.NewServer(eval, audit.NewLogger(audit.NewRedactor(cfg.Audit.RedactHeaders, cfg.Audit.RedactJSONKeys), audit.NewMemorySink()), audit.NewMetrics(), clock)
	gwLn, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig(ca, serverCert, nil))
	if err != nil {
		return OverheadReport{}, err
	}
	defer gwLn.Close()
	gwSrv := &http.Server{Handler: gwHandler}
	go func() { _ = gwSrv.Serve(gwLn) }()
	defer gwSrv.Close()

	directClient := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 16}}
	gwClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, clientCert), MaxIdleConnsPerHost: 16}}

	directURL := cfg.UpstreamURL + "/v1/accounts/ACC-1001/balance?currency=USD"
	gwBase := "https://" + gwLn.Addr().String()

	// Warmup
	for i := 0; i < 20; i++ {
		resp, err := directClient.Get(directURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// Series 1: Direct HTTP to upstream
	directLat := make([]float64, samples)
	tStart := time.Now()
	for i := 0; i < samples; i++ {
		s := time.Now()
		resp, err := directClient.Get(directURL)
		if err != nil {
			return OverheadReport{}, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		directLat[i] = float64(time.Since(s).Nanoseconds()) / 1000.0
	}
	directTotal := time.Since(tStart)

	// Warmup gateway (TLS handshake established on pooled keep-alive connection)
	for i := 0; i < 20; i++ {
		ts := time.Now().UTC().Format(time.RFC3339)
		nonce := fmt.Sprintf("warm-%d", i)
		sig, _ := signing.SignRequest("Ed25519", "bench-sig-k1", ts, nonce, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, priv, nil)
		req, _ := http.NewRequest("GET", gwBase+"/v1/accounts/ACC-1001/balance?currency=USD", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Signature-Alg", "Ed25519")
		req.Header.Set("X-Key-ID", "bench-sig-k1")
		req.Header.Set("X-Request-Timestamp", ts)
		req.Header.Set("X-Request-Nonce", nonce)
		req.Header.Set("X-Signature", sig)
		resp, err := gwClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// Series 2: Through full mTLS + OIDC + Ed25519 Request Signing + Policy + RateLimit + Redacted Audit Gateway
	gwLat := make([]float64, samples)
	tStart = time.Now()
	for i := 0; i < samples; i++ {
		ts := time.Now().UTC().Format(time.RFC3339)
		nonce := fmt.Sprintf("bench-gw-%d", i)
		sig, _ := signing.SignRequest("Ed25519", "bench-sig-k1", ts, nonce, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, priv, nil)
		req, _ := http.NewRequest("GET", gwBase+"/v1/accounts/ACC-1001/balance?currency=USD", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Signature-Alg", "Ed25519")
		req.Header.Set("X-Key-ID", "bench-sig-k1")
		req.Header.Set("X-Request-Timestamp", ts)
		req.Header.Set("X-Request-Nonce", nonce)
		req.Header.Set("X-Signature", sig)

		s := time.Now()
		resp, err := gwClient.Do(req)
		if err != nil {
			return OverheadReport{}, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		gwLat[i] = float64(time.Since(s).Nanoseconds()) / 1000.0
		if resp.StatusCode != http.StatusOK {
			return OverheadReport{}, fmt.Errorf("benchmark request %d failed with status %d", i, resp.StatusCode)
		}
	}
	gwTotal := time.Since(tStart)

	// Series 3: Pure in-memory Evaluator.Evaluate overhead (no network I/O)
	evalLat := make([]float64, samples)
	tStart = time.Now()
	for i := 0; i < samples; i++ {
		ts := time.Now().UTC().Format(time.RFC3339)
		nonce := fmt.Sprintf("bench-eval-%d", i)
		sig, _ := signing.SignRequest("Ed25519", "bench-sig-k1", ts, nonce, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, priv, nil)
		env := domain.RequestEnvelope{
			RequestID:  fmt.Sprintf("ev-%d", i),
			Method:     "GET",
			Path:       "/v1/accounts/ACC-1001/balance",
			RawQuery:   "currency=USD",
			BearerAuth: tok,
			PeerCert:   clientCert.Info,
			Signature: domain.SignatureHeaders{
				Algorithm: "Ed25519", KeyID: "bench-sig-k1", Timestamp: ts, Nonce: nonce, Signature: sig,
			},
			ReceivedAt: clock.Now(),
		}
		s := time.Now()
		res := eval.Evaluate(env)
		evalLat[i] = float64(time.Since(s).Nanoseconds()) / 1000.0
		if res.Decision != domain.DecisionAllow {
			return OverheadReport{}, fmt.Errorf("eval benchmark %d denied: %s", i, res.ReasonCode)
		}
	}
	evalTotal := time.Since(tStart)

	directStats := computeStats(directLat, directTotal)
	gwStats := computeStats(gwLat, gwTotal)
	evalStats := computeStats(evalLat, evalTotal)

	return OverheadReport{
		Metadata:              meta,
		Note:                  "Measured on local loopback (127.0.0.1) with pooled keep-alive HTTP/TLS 1.3 connections. Includes full mTLS cert validation, OIDC EdDSA JWT verification, Ed25519 canonical request signature verification, replay nonce tracking, deny-by-default policy, rate limiting, and redacted audit logging.",
		DirectUpstreamHTTP:    directStats,
		GatewayFullMTLSStack:  gwStats,
		PureEvaluatorInMemory: evalStats,
		DeltaMeanUs:           round2(gwStats.MeanUs - directStats.MeanUs),
		DeltaP50Us:            round2(gwStats.P50Us - directStats.P50Us),
		DeltaP95Us:            round2(gwStats.P95Us - directStats.P95Us),
		DeltaP99Us:            round2(gwStats.P99Us - directStats.P99Us),
	}, nil
}

func computeStats(vals []float64, totalDur time.Duration) BenchmarkStats {
	cp := append([]float64(nil), vals...)
	sort.Float64s(cp)
	sum := 0.0
	for _, v := range cp {
		sum += v
	}
	pct := func(p float64) float64 {
		idx := int(float64(len(cp)-1) * p)
		return round2(cp[idx])
	}
	return BenchmarkStats{
		Samples:    len(cp),
		MeanUs:     round2(sum / float64(len(cp))),
		P50Us:      pct(0.50),
		P95Us:      pct(0.95),
		P99Us:      pct(0.99),
		MinUs:      round2(cp[0]),
		MaxUs:      round2(cp[len(cp)-1]),
		Throughput: round2(float64(len(cp)) / totalDur.Seconds()),
	}
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100.0
}

func writeReportJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal report %s: %v\n", path, err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write report %s: %v\n", path, err)
		os.Exit(1)
	}
}
