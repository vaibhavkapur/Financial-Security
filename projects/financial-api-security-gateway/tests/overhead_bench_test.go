package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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

func BenchmarkEvaluatorFullPipeline(b *testing.B) {
	cfg, err := domain.LoadGatewayConfig("../config/gateway.json")
	if err != nil {
		b.Fatal(err)
	}
	ps, err := domain.LoadPolicySet("../config/policies.json")
	if err != nil {
		b.Fatal(err)
	}
	reg, err := domain.LoadClientRegistry("../config/clients.json")
	if err != nil {
		b.Fatal(err)
	}
	for i := range ps.Rules {
		ps.Rules[i].RateLimitRPS = 1_000_000
		ps.Rules[i].RateLimitBurst = 1_000_000
	}

	clock := domain.NewFixedClock(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	kr := oidc.NewKeyRing()
	_, _ = kr.AddEd25519Key("bench-oidc-k1", nil, nil, true, clock.Now())
	issuer := oidc.NewIssuer(kr)
	tok, _ := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
		JWTID: "jti-bench", Scopes: []string{"accounts:read"}, CertThumbprint: "bench-thumb",
		IssuedAt: clock.Now(), NotBefore: clock.Now(), ExpiresAt: clock.Now().Add(1 * time.Hour),
	})

	sigKeys := signing.NewKeyStore()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sigKeys.AddEd25519Key("bench-sig-k1", "cli-ledger-reader", pub)

	polEngine, _ := policy.NewEngine(ps, reg)
	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, kr, oidc.NewMemoryTokenRevocationStore(), clock),
		RequestVerifier: signing.NewRequestVerifier(cfg.Signing, sigKeys, signing.NewMemoryNonceStore(100000), clock),
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: pki.NewMemoryCertRevocationStore(),
	}

	ts := clock.Now().Format(time.RFC3339)
	envelopes := make([]domain.RequestEnvelope, b.N)
	for i := 0; i < b.N; i++ {
		nonce := fmt.Sprintf("bn-%d", i)
		sig, _ := signing.SignRequest("Ed25519", "bench-sig-k1", ts, nonce, "GET", "/v1/accounts/ACC-1001/balance", "currency=USD", nil, priv, nil)
		envelopes[i] = domain.RequestEnvelope{
			RequestID:  nonce,
			Method:     "GET",
			Path:       "/v1/accounts/ACC-1001/balance",
			RawQuery:   "currency=USD",
			BearerAuth: tok,
			PeerCert:   domain.PeerCertInfo{Present: true, CommonName: "cli-ledger-reader", ThumbprintSHA256: "bench-thumb"},
			Signature:  domain.SignatureHeaders{Algorithm: "Ed25519", KeyID: "bench-sig-k1", Timestamp: ts, Nonce: nonce, Signature: sig},
			ReceivedAt: clock.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eval.Evaluate(envelopes[i])
		if res.Decision != domain.DecisionAllow {
			b.Fatalf("unexpected deny: %s", res.ReasonCode)
		}
	}
}
