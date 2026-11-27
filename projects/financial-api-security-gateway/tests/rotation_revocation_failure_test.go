package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
	"github.com/financial-security/financial-api-security-gateway/src/gateway"
	"github.com/financial-security/financial-api-security-gateway/src/oidc"
	"github.com/financial-security/financial-api-security-gateway/src/pki"
	"github.com/financial-security/financial-api-security-gateway/src/policy"
	"github.com/financial-security/financial-api-security-gateway/src/ratelimit"
	"github.com/financial-security/financial-api-security-gateway/src/signing"
)

func TestKeyRotationAndRevocation(t *testing.T) {
	env := startLiveGatewayEnv(t, 500)
	defer env.cleanup()

	readerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.readerCert)}}
	tokK1 := env.mint(t, "cli-ledger-reader", "jti-rot-1", env.readerCert.Info.ThumbprintSHA256, []string{"accounts:read"})

	// 1. Rotate OIDC signing key to oidc-live-k2 (dual-key overlap window).
	if _, err := env.keyRing.RotateToNewEd25519Key("oidc-live-k2", env.clock.Now()); err != nil {
		t.Fatalf("rotate oidc key: %v", err)
	}
	tokK2 := env.mint(t, "cli-ledger-reader", "jti-rot-2", env.readerCert.Info.ThumbprintSHA256, []string{"accounts:read"})

	// Verify JWKS exposes both public keys and no private material.
	jwksRaw, err := env.keyRing.JWKSJSON()
	if err != nil {
		t.Fatalf("jwks json: %v", err)
	}
	if !strings.Contains(string(jwksRaw), "oidc-live-k1") || !strings.Contains(string(jwksRaw), "oidc-live-k2") {
		t.Errorf("expected both keys in JWKS during overlap window: %s", string(jwksRaw))
	}

	// Both old and new OIDC tokens succeed during grace window.
	resp, _, err := env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK1, "sig-reader-1", "rot-n1", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("old key token request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("old key token should pass during overlap window, got status=%d", resp.StatusCode)
	}
	resp, _, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK2, "sig-reader-1", "rot-n2", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("new key token request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new key token should pass, got status=%d", resp.StatusCode)
	}

	// 2. Revoke old OIDC key -> old token immediately rejected, new token still passes.
	if err := env.keyRing.RevokeKey("oidc-live-k1", env.clock.Now()); err != nil {
		t.Fatalf("revoke old key: %v", err)
	}
	resp, body, err := env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK1, "sig-reader-1", "rot-n3", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("revoked old key token request error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonTokenKeyRevoked)) {
		t.Fatalf("expected 401 ERR_TOKEN_KEY_REVOKED, got status=%d body=%s", resp.StatusCode, string(body))
	}
	resp, _, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK2, "sig-reader-1", "rot-n4", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("new key token after old revocation failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new key token should still pass after old key revocation, got status=%d", resp.StatusCode)
	}

	// 3. Client request-signing key rotation & revocation.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	env.sigKeys.AddEd25519Key("sig-reader-2", "cli-ledger-reader", newPub)
	resp, _, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK2, "sig-reader-2", "rot-n5", env.clock.Now(), newPriv, nil)
	if err != nil {
		t.Fatalf("rotated client signing key request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotated client signing key should pass, got status=%d", resp.StatusCode)
	}
	_ = env.sigKeys.RevokeKey("sig-reader-1")
	resp, body, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK2, "sig-reader-1", "rot-n6", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("revoked client signing key request error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonSigKeyRevoked)) {
		t.Fatalf("revoked client signing key should fail with ERR_SIG_KEY_REVOKED, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 4. Individual JTI token revocation.
	env.jtiRevocations.RevokeJTI("jti-rot-2", env.clock.Now().Add(10*time.Minute))
	resp, body, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK2, "sig-reader-2", "rot-n7", env.clock.Now(), newPriv, nil)
	if err != nil {
		t.Fatalf("revoked JTI request error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonTokenRevoked)) {
		t.Fatalf("revoked JTI token should fail with ERR_TOKEN_REVOKED, got status=%d body=%s", resp.StatusCode, string(body))
	}

	// 5. Live mTLS certificate revocation (rejects both kept-alive and fresh TLS connections).
	tokK3 := env.mint(t, "cli-ledger-reader", "jti-rot-3", env.readerCert.Info.ThumbprintSHA256, []string{"accounts:read"})
	env.certRevocations.Revoke(env.readerCert.Info.SerialHex, "key-compromise")
	resp, body, err = env.signedRequest(t, readerClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK3, "sig-reader-2", "rot-n8", env.clock.Now(), newPriv, nil)
	if err == nil {
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), string(domain.ReasonMTLSRevoked)) {
			t.Fatalf("kept-alive revoked cert should return 401 ERR_MTLS_REVOKED, got status=%d body=%s", resp.StatusCode, string(body))
		}
	}
	// Fresh connection with revoked cert MUST fail TLS handshake.
	freshRevokedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.readerCert)}}
	if _, _, err := env.signedRequest(t, freshRevokedClient, "GET", "/v1/accounts/ACC-1001/balance", "", nil, tokK3, "sig-reader-2", "rot-n9", env.clock.Now(), newPriv, nil); err == nil {
		t.Errorf("fresh TLS connection with revoked cert should fail handshake")
	}
}

func TestUpstreamTimeoutFailureBehavior(t *testing.T) {
	env := startLiveGatewayEnv(t, 100) // 100ms strict upstream timeout
	defer env.cleanup()

	readerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLSConfig(env.ca, env.readerCert)}}
	tok := env.mint(t, "cli-ledger-reader", "jti-to-1", env.readerCert.Info.ThumbprintSHA256, []string{"accounts:read"})

	// Upstream delays 400ms -> gateway must enforce 100ms timeout and return 504 ERR_UPSTREAM_TIMEOUT.
	resp, body, err := env.signedRequest(t, readerClient, "GET", "/v1/slow", "delay_ms=400", nil, tok, "sig-reader-1", "to-n1", env.clock.Now(), env.readerPriv, nil)
	if err != nil {
		t.Fatalf("unexpected transport error on gateway timeout test: %v", err)
	}
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 Gateway Timeout, got %d body=%s", resp.StatusCode, string(body))
	}
	var er domain.ErrorResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if er.ErrorCode != domain.ReasonUpstreamTimeout {
		t.Errorf("expected error_code %s, got %s", domain.ReasonUpstreamTimeout, er.ErrorCode)
	}
	if snap := env.metrics.Snapshot(); snap.UpstreamTimeouts != 1 {
		t.Errorf("expected UpstreamTimeouts metric == 1, got %d", snap.UpstreamTimeouts)
	}
}

func TestOperationalConfigValidationAndUnsupportedInputs(t *testing.T) {
	// Missing config file
	if _, err := domain.LoadGatewayConfig(filepath.Join("..", "config", "does_not_exist.json")); err == nil {
		t.Errorf("expected error loading missing config file")
	}
	// Missing required issuer field fixture
	if _, err := domain.LoadGatewayConfig(filepath.Join("..", "config", "invalid_missing_issuer.json")); err == nil || !strings.Contains(err.Error(), "oidc.issuer") {
		t.Errorf("expected oidc.issuer validation error, got %v", err)
	}
	// Disabling deny_by_default must fail validation
	cfg, ps, reg := loadTestConfig(t)
	cfg.DenyByDefault = false
	if err := domain.ValidateGatewayConfig(cfg); err == nil || !strings.Contains(err.Error(), "deny_by_default") {
		t.Errorf("expected deny_by_default invariant error, got %v", err)
	}

	// Unsupported HTTP method (TRACE) must return explicit 405 ERR_METHOD_UNSUPPORTED
	cfg.DenyByDefault = true
	clock := domain.NewFixedClock(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	polEngine, _ := policy.NewEngine(ps, reg)
	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, oidc.NewKeyRing(), oidc.NewMemoryTokenRevocationStore(), clock),
		RequestVerifier: signing.NewRequestVerifier(cfg.Signing, signing.NewKeyStore(), signing.NewMemoryNonceStore(100), clock),
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
	}
	res := eval.Evaluate(domain.RequestEnvelope{RequestID: "op-1", Method: "TRACE", Path: "/v1/accounts/ACC-1001/balance"})
	if res.Decision != domain.DecisionDeny || res.ReasonCode != domain.ReasonMethodUnsupported || res.HTTPStatus != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 ERR_METHOD_UNSUPPORTED, got %+v", res)
	}

	// Oversized body must be rejected explicitly
	oversized := make([]byte, cfg.Audit.MaxBodyBytes+10)
	res = eval.Evaluate(domain.RequestEnvelope{RequestID: "op-2", Method: "POST", Path: "/v1/orders", Body: oversized})
	if res.Decision != domain.DecisionDeny || res.ReasonCode != domain.ReasonBodyTooLarge || res.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 ERR_BODY_TOO_LARGE, got %+v", res)
	}
}

func TestDeterministicReproducibility(t *testing.T) {
	runOnce := func() string {
		fx := loadFixture(t)
		cfg, ps, reg := loadTestConfig(t)
		fixedTime, _ := time.Parse(time.RFC3339, fx.FixedClockUTC)
		clock := domain.NewFixedClock(fixedTime)

		// Deterministic Ed25519 key from fixed 32-byte seed.
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = byte((fx.Seed + i*7) % 251)
		}
		edPriv := ed25519.NewKeyFromSeed(seed)
		edPub := edPriv.Public().(ed25519.PublicKey)

		kr := oidc.NewKeyRing()
		_, _ = kr.AddEd25519Key("det-k1", edPub, edPriv, true, fixedTime)
		issuer := oidc.NewIssuer(kr)
		tok, _ := issuer.MintToken(oidc.MintParams{
			Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
			JWTID: "jti-det-1", Scopes: []string{"accounts:read"}, CertThumbprint: "det-thumb",
			IssuedAt: fixedTime, NotBefore: fixedTime, ExpiresAt: fixedTime.Add(5 * time.Minute),
		})

		sk := signing.NewKeyStore()
		sk.AddHMACKey("det-hmac", "cli-ledger-reader", []byte("deterministic-secret"))
		polEngine, _ := policy.NewEngine(ps, reg)
		eval := &gateway.Evaluator{
			Config:          cfg,
			PolicyEngine:    polEngine,
			TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, kr, oidc.NewMemoryTokenRevocationStore(), clock),
			RequestVerifier: signing.NewRequestVerifier(cfg.Signing, sk, signing.NewMemoryNonceStore(100), clock),
			RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		}

		var outputs []domain.EvaluationResult
		for _, tc := range []struct {
			id, method, path, nonce string
		}{
			{"r1", "GET", "/v1/accounts/ACC-1001/balance", "n1"},
			{"r2", "GET", "/v1/accounts/ACC-1001/balance", "n1"}, // replay
			{"r3", "POST", "/v1/orders", "n2"},                   // role forbidden
			{"r4", "DELETE", "/v1/unknown", "n3"},                // default deny
		} {
			ts := fixedTime.Format(time.RFC3339)
			sig, _ := signing.SignRequest("HMAC-SHA256", "det-hmac", ts, tc.nonce, tc.method, tc.path, "", nil, nil, []byte("deterministic-secret"))
			res := eval.Evaluate(domain.RequestEnvelope{
				RequestID: tc.id, Method: tc.method, Path: tc.path, BearerAuth: tok,
				PeerCert:  domain.PeerCertInfo{Present: true, CommonName: "cli-ledger-reader", ThumbprintSHA256: "det-thumb"},
				Signature: domain.SignatureHeaders{Algorithm: "HMAC-SHA256", KeyID: "det-hmac", Timestamp: ts, Nonce: tc.nonce, Signature: sig},
			})
			outputs = append(outputs, res)
		}
		b, _ := json.Marshal(outputs)
		return string(b)
	}

	out1 := runOnce()
	out2 := runOnce()
	if out1 != out2 {
		t.Fatalf("non-deterministic evaluation output!\nrun1: %s\nrun2: %s", out1, out2)
	}
}
