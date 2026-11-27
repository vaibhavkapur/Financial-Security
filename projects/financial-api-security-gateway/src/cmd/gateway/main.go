package main

import (
	"bytes"
	"context"
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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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

func main() {
	configDir := flag.String("config-dir", "config", "Directory containing gateway.json, policies.json, and clients.json")
	demo := flag.Bool("demo", false, "Run the self-contained local-lab end-to-end security demo")
	validateOnly := flag.Bool("validate-config", false, "Validate configuration files and exit")
	serve := flag.Bool("serve", false, "Run the live mTLS gateway and simulated financial API")
	outputAudit := flag.String("output-audit", "reports/audit_sample.jsonl", "Output path for redacted JSONL audit log in demo/serve mode")
	flag.Parse()

	cfg, ps, reg, err := loadAllConfig(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CONFIGURATION ERROR: %v\n", err)
		os.Exit(1)
	}

	if *validateOnly {
		fmt.Printf("Configuration valid (schema=%s, policy=%s, rules=%d, clients=%d, deny_by_default=%v)\n",
			cfg.SchemaVersion, ps.PolicyVersion, len(ps.Rules), len(reg.Clients), cfg.DenyByDefault)
		return
	}

	if *demo {
		if err := runDemo(cfg, ps, reg, *outputAudit); err != nil {
			fmt.Fprintf(os.Stderr, "DEMO FAILED: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *serve {
		if err := runServer(cfg, ps, reg, *outputAudit); err != nil {
			fmt.Fprintf(os.Stderr, "SERVER ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("Financial API Security Gateway (Local Lab Prototype)")
	fmt.Println("Usage: gateway [--validate-config | --demo | --serve] [--config-dir config] [--output-audit reports/audit_sample.jsonl]")
}

func loadAllConfig(dir string) (domain.GatewayConfig, domain.PolicySet, domain.ClientRegistry, error) {
	cfg, err := domain.LoadGatewayConfig(filepath.Join(dir, "gateway.json"))
	if err != nil {
		return domain.GatewayConfig{}, domain.PolicySet{}, domain.ClientRegistry{}, err
	}
	ps, err := domain.LoadPolicySet(filepath.Join(dir, "policies.json"))
	if err != nil {
		return domain.GatewayConfig{}, domain.PolicySet{}, domain.ClientRegistry{}, err
	}
	reg, err := domain.LoadClientRegistry(filepath.Join(dir, "clients.json"))
	if err != nil {
		return domain.GatewayConfig{}, domain.PolicySet{}, domain.ClientRegistry{}, err
	}
	return cfg, ps, reg, nil
}

func runDemo(cfg domain.GatewayConfig, ps domain.PolicySet, reg domain.ClientRegistry, auditPath string) error {
	clock := domain.RealClock{}
	cfg.UpstreamTimeoutMs = 150

	// 1. Start simulated financial upstream API.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer upstreamLn.Close()
	upstreamSrv := &http.Server{Handler: mockapi.NewSimulatedFinancialAPI().Handler()}
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()
	defer upstreamSrv.Close()
	cfg.UpstreamURL = "http://" + upstreamLn.Addr().String()

	// 2. Initialize local-lab Test CA, mTLS server/client certs, and revocation store.
	ca, err := pki.NewTestCA("FinSec Local-Lab Root CA", clock)
	if err != nil {
		return err
	}
	serverCert, err := ca.IssueServerCert("gateway.finsec.local", 2*time.Hour)
	if err != nil {
		return err
	}
	readerCert, err := ca.IssueClientCert("cli-ledger-reader", "spiffe://finsec.local/clients/cli-ledger-reader", 2*time.Hour)
	if err != nil {
		return err
	}
	routerCert, err := ca.IssueClientCert("cli-order-router", "spiffe://finsec.local/clients/cli-order-router", 2*time.Hour)
	if err != nil {
		return err
	}
	certRevocations := pki.NewMemoryCertRevocationStore()

	// 3. Initialize mock OIDC KeyRing + Issuer + Verifier.
	keyRing := oidc.NewKeyRing()
	if _, err := keyRing.AddEd25519Key("oidc-ed25519-k1", nil, nil, true, clock.Now()); err != nil {
		return err
	}
	issuer := oidc.NewIssuer(keyRing)
	jtiRevocations := oidc.NewMemoryTokenRevocationStore()
	tokenVerifier := oidc.NewVerifier(cfg.OIDC, cfg.RequireCertBoundToken, keyRing, jtiRevocations, clock)

	// 4. Initialize request signing keys + replay store.
	sigKeys := signing.NewKeyStore()
	readerPub, readerPriv, _ := ed25519.GenerateKey(rand.Reader)
	routerPub, routerPriv, _ := ed25519.GenerateKey(rand.Reader)
	sigKeys.AddEd25519Key("sig-reader-k1", "cli-ledger-reader", readerPub)
	sigKeys.AddEd25519Key("sig-router-k1", "cli-order-router", routerPub)
	nonceStore := signing.NewMemoryNonceStore(cfg.Signing.MaxNonceEntries)
	reqVerifier := signing.NewRequestVerifier(cfg.Signing, sigKeys, nonceStore, clock)

	// 5. Initialize policy engine, rate limiter, redacted audit logger, and gateway server.
	polEngine, err := policy.NewEngine(ps, reg)
	if err != nil {
		return err
	}
	limiter := ratelimit.NewTokenBucketLimiter(clock)
	memSink := audit.NewMemorySink()
	var sink audit.Sink = memSink
	var fileSink *audit.JSONLSink
	if auditPath != "" {
		fileSink, err = audit.NewJSONLSink(auditPath)
		if err != nil {
			return err
		}
		defer fileSink.Close()
		sink = audit.NewMultiSink(memSink, fileSink)
	}
	auditLogger := audit.NewLogger(audit.NewRedactor(cfg.Audit.RedactHeaders, cfg.Audit.RedactJSONKeys), sink)
	metrics := audit.NewMetrics()

	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   tokenVerifier,
		RequestVerifier: reqVerifier,
		RateLimiter:     limiter,
		CertRevocations: certRevocations,
	}
	gwHandler, err := gateway.NewServer(eval, auditLogger, metrics, clock)
	if err != nil {
		return err
	}

	gwLn, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig(ca, serverCert, certRevocations))
	if err != nil {
		return err
	}
	defer gwLn.Close()
	gwSrv := &http.Server{Handler: gwHandler}
	go func() { _ = gwSrv.Serve(gwLn) }()
	defer gwSrv.Close()
	baseURL := "https://" + gwLn.Addr().String()

	readerHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, readerCert)}}
	routerHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(ca, routerCert)}}

	now := clock.Now()
	readerTok, _ := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
		JWTID: "jti-demo-reader-1", Scopes: []string{"accounts:read"},
		CertThumbprint: readerCert.Info.ThumbprintSHA256,
		IssuedAt: now, NotBefore: now.Add(-5 * time.Second), ExpiresAt: now.Add(5 * time.Minute),
	})
	routerTok, _ := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-order-router", Audience: cfg.OIDC.Audience,
		JWTID: "jti-demo-router-1", Scopes: []string{"accounts:read", "orders:write"},
		CertThumbprint: routerCert.Info.ThumbprintSHA256,
		IssuedAt: now, NotBefore: now.Add(-5 * time.Second), ExpiresAt: now.Add(5 * time.Minute),
	})

	fmt.Println("=== Financial API Security Gateway — Local-Lab Demo ===")
	fmt.Printf("Gateway mTLS endpoint: %s | Upstream mock API: %s\n\n", baseURL, cfg.UpstreamURL)

	sendSigned := func(client *http.Client, method, path, query string, body []byte, token, keyID, nonce string, priv ed25519.PrivateKey) (int, string, error) {
		ts := time.Now().UTC().Format(time.RFC3339)
		sig, err := signing.SignRequest("Ed25519", keyID, ts, nonce, method, path, query, body, priv, nil)
		if err != nil {
			return 0, "", err
		}
		fullURL := baseURL + path
		if query != "" {
			fullURL += "?" + query
		}
		req, _ := http.NewRequest(method, fullURL, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("X-Signature-Alg", "Ed25519")
		req.Header.Set("X-Key-ID", keyID)
		req.Header.Set("X-Request-Timestamp", ts)
		req.Header.Set("X-Request-Nonce", nonce)
		req.Header.Set("X-Signature", sig)
		req.Header.Set("X-Api-Key", "synthetic-canary-api-key-never-log")
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b)), nil
	}

	// Step 1: Valid GET balance
	st, body, err := sendSigned(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-k1", "demo-nonce-001", readerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[1] Valid mTLS+OIDC+Signed GET balance      -> HTTP %d | %s\n", st, body)

	// Step 2: Valid POST paper order
	orderBody := []byte(`{"account_id":"ACC-1001","symbol":"SIM-AAPL","side":"BUY","qty":5,"limit_price":151.00}`)
	st, body, err = sendSigned(routerHTTP, "POST", "/v1/orders", "", orderBody, routerTok, "sig-router-k1", "demo-nonce-002", routerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[2] Valid mTLS+OIDC+Signed POST paper order -> HTTP %d | %s\n", st, body)

	// Step 3: Replay attack (reusing demo-nonce-001)
	st, body, err = sendSigned(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, readerTok, "sig-reader-k1", "demo-nonce-001", readerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[3] Replayed nonce rejected                 -> HTTP %d | %s\n", st, body)

	// Step 4: Scope/role escalation (ledger reader attempting POST /v1/orders)
	st, body, err = sendSigned(readerHTTP, "POST", "/v1/orders", "", orderBody, readerTok, "sig-reader-k1", "demo-nonce-003", readerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[4] Scope/role escalation denied            -> HTTP %d | %s\n", st, body)

	// Step 5: Unmatched route denied by default
	st, body, err = sendSigned(routerHTTP, "DELETE", "/v1/admin/reset", "", nil, routerTok, "sig-router-k1", "demo-nonce-004", routerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[5] Unknown route denied by default         -> HTTP %d | %s\n", st, body)

	// Step 6: OIDC Key Rotation + old key revocation
	if _, err := keyRing.RotateToNewEd25519Key("oidc-ed25519-k2", clock.Now()); err != nil {
		return err
	}
	rotatedTok, _ := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
		JWTID: "jti-demo-reader-2", Scopes: []string{"accounts:read"},
		CertThumbprint: readerCert.Info.ThumbprintSHA256,
		IssuedAt: now, NotBefore: now.Add(-5 * time.Second), ExpiresAt: now.Add(5 * time.Minute),
	})
	st, _, err = sendSigned(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, rotatedTok, "sig-reader-k1", "demo-nonce-005", readerPriv)
	if err != nil {
		return err
	}
	_ = keyRing.RevokeKey("oidc-ed25519-k1", clock.Now())
	stOld, bodyOld, err := sendSigned(readerHTTP, "GET", "/v1/accounts/ACC-1001/balance", "", nil, readerTok, "sig-reader-k1", "demo-nonce-006", readerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[6] OIDC rotation (new kid=%d, revoked old kid=%d) | %s\n", st, stOld, bodyOld)

	// Step 7: Upstream timeout
	st, body, err = sendSigned(readerHTTP, "GET", "/v1/slow", "delay_ms=400", nil, rotatedTok, "sig-reader-k1", "demo-nonce-007", readerPriv)
	if err != nil {
		return err
	}
	fmt.Printf("[7] Upstream timeout handled                -> HTTP %d | %s\n", st, body)

	// Verify audit logs contain zero secrets
	for _, ev := range memSink.Events() {
		raw, _ := json.Marshal(ev)
		s := string(raw)
		if strings.Contains(s, "synthetic-canary-api-key-never-log") || strings.Contains(s, "eyJ") || strings.Contains(s, readerTok) {
			return fmt.Errorf("SECRET LEAK DETECTED in audit event %s", ev.EventID)
		}
	}

	snap, _ := json.MarshalIndent(metrics.Snapshot(), "", "  ")
	fmt.Printf("\nAudit log written to: %s (%d events, 0 secrets leaked)\n", auditPath, len(memSink.Events()))
	fmt.Printf("Diagnostic Metrics Snapshot:\n%s\n", string(snap))
	return nil
}

func runServer(cfg domain.GatewayConfig, ps domain.PolicySet, reg domain.ClientRegistry, auditPath string) error {
	clock := domain.RealClock{}
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer upstreamLn.Close()
	upstreamSrv := &http.Server{Handler: mockapi.NewSimulatedFinancialAPI().Handler()}
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()
	defer upstreamSrv.Close()
	cfg.UpstreamURL = "http://" + upstreamLn.Addr().String()

	ca, err := pki.NewTestCA("FinSec Local-Lab Root CA", clock)
	if err != nil {
		return err
	}
	serverCert, err := ca.IssueServerCert("gateway.finsec.local", 24*time.Hour)
	if err != nil {
		return err
	}
	certRevocations := pki.NewMemoryCertRevocationStore()
	keyRing := oidc.NewKeyRing()
	_, _ = keyRing.AddEd25519Key("oidc-ed25519-k1", nil, nil, true, clock.Now())
	tokenVerifier := oidc.NewVerifier(cfg.OIDC, cfg.RequireCertBoundToken, keyRing, oidc.NewMemoryTokenRevocationStore(), clock)
	reqVerifier := signing.NewRequestVerifier(cfg.Signing, signing.NewKeyStore(), signing.NewMemoryNonceStore(cfg.Signing.MaxNonceEntries), clock)
	polEngine, err := policy.NewEngine(ps, reg)
	if err != nil {
		return err
	}
	fileSink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		return err
	}
	defer fileSink.Close()
	gwHandler, err := gateway.NewServer(&gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   tokenVerifier,
		RequestVerifier: reqVerifier,
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: certRevocations,
	}, audit.NewLogger(audit.NewRedactor(cfg.Audit.RedactHeaders, cfg.Audit.RedactJSONKeys), fileSink), audit.NewMetrics(), clock)
	if err != nil {
		return err
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, pki.ServerTLSConfig(ca, serverCert, certRevocations))
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: gwHandler}
	fmt.Printf("Local-lab mTLS Financial API Security Gateway listening on https://%s (upstream %s)\n", ln.Addr().String(), cfg.UpstreamURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
