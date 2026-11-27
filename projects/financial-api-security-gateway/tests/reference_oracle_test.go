package tests

import (
	"encoding/base64"
	"encoding/json"
	"os"
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

type referenceFixture struct {
	SchemaVersion        string `json:"schema_version"`
	FixtureID            string `json:"fixture_id"`
	Seed                 int    `json:"seed"`
	FixedClockUTC        string `json:"fixed_clock_utc"`
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
	DecisionReferenceCases []struct {
		ID               string   `json:"id"`
		Description      string   `json:"description"`
		ClientID         string   `json:"client_id"`
		Method           string   `json:"method"`
		Path             string   `json:"path"`
		RawQuery         string   `json:"raw_query"`
		Scopes           []string `json:"scopes"`
		TokenMutation    string   `json:"token_mutation"`
		ExpectedDecision string   `json:"expected_decision"`
		ExpectedReason   string   `json:"expected_reason"`
		ExpectedStatus   int      `json:"expected_status"`
	} `json:"decision_reference_cases"`
}

func loadFixture(t *testing.T) referenceFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "data", "fixtures", "reference_vectors.json"))
	if err != nil {
		t.Fatalf("read reference_vectors.json: %v", err)
	}
	var fx referenceFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse reference_vectors.json: %v", err)
	}
	return fx
}

func loadTestConfig(t *testing.T) (domain.GatewayConfig, domain.PolicySet, domain.ClientRegistry) {
	t.Helper()
	cfg, err := domain.LoadGatewayConfig(filepath.Join("..", "config", "gateway.json"))
	if err != nil {
		t.Fatalf("load gateway config: %v", err)
	}
	ps, err := domain.LoadPolicySet(filepath.Join("..", "config", "policies.json"))
	if err != nil {
		t.Fatalf("load policy set: %v", err)
	}
	reg, err := domain.LoadClientRegistry(filepath.Join("..", "config", "clients.json"))
	if err != nil {
		t.Fatalf("load client registry: %v", err)
	}
	return cfg, ps, reg
}

func TestIndependentSigningOracleVectors(t *testing.T) {
	fx := loadFixture(t)
	if len(fx.SigningOracleVectors) < 2 {
		t.Fatalf("expected at least 2 signing oracle vectors")
	}

	for _, vec := range fx.SigningOracleVectors {
		t.Run(vec.ID, func(t *testing.T) {
			canonical, bodySHA := signing.CanonicalRequestString(
				vec.Method, vec.Path, vec.RawQuery, vec.Timestamp, vec.Nonce, vec.KeyID, []byte(vec.Body),
			)
			if bodySHA != vec.ExpectedBodySHA256 {
				t.Errorf("body sha256 mismatch:\n got:  %s\n want: %s", bodySHA, vec.ExpectedBodySHA256)
			}
			if canonical != vec.ExpectedCanonicalString {
				t.Errorf("canonical string mismatch:\n got:  %q\n want: %q", canonical, vec.ExpectedCanonicalString)
			}
			sig := signing.SignHMACSHA256([]byte(vec.SyntheticSecret), canonical)
			if sig != vec.ExpectedSignatureB64URL {
				t.Errorf("HMAC-SHA256 oracle mismatch:\n got:  %s\n want: %s", sig, vec.ExpectedSignatureB64URL)
			}
			if !signing.VerifyHMACSHA256([]byte(vec.SyntheticSecret), canonical, vec.ExpectedSignatureB64URL) {
				t.Errorf("VerifyHMACSHA256 rejected oracle signature")
			}
			// Tampered body must fail verification.
			tamperedCanonical, _ := signing.CanonicalRequestString(
				vec.Method, vec.Path, vec.RawQuery, vec.Timestamp, vec.Nonce, vec.KeyID, []byte(vec.Body+" "),
			)
			if signing.VerifyHMACSHA256([]byte(vec.SyntheticSecret), tamperedCanonical, vec.ExpectedSignatureB64URL) {
				t.Errorf("VerifyHMACSHA256 accepted tampered body")
			}
		})
	}
}

func TestDomainReferenceDecisionCases(t *testing.T) {
	fx := loadFixture(t)
	cfg, ps, reg := loadTestConfig(t)

	fixedTime, err := time.Parse(time.RFC3339, fx.FixedClockUTC)
	if err != nil {
		t.Fatalf("parse fixed clock: %v", err)
	}
	clock := domain.NewFixedClock(fixedTime)

	keyRing := oidc.NewKeyRing()
	if _, err := keyRing.AddEd25519Key("ref-oidc-k1", nil, nil, true, fixedTime); err != nil {
		t.Fatalf("add oidc key: %v", err)
	}
	// Also test ES256 support in key ring
	if _, err := keyRing.AddES256Key("ref-oidc-es256", nil, false, fixedTime); err != nil {
		t.Fatalf("add es256 key: %v", err)
	}
	issuer := oidc.NewIssuer(keyRing)

	sigKeys := signing.NewKeyStore()
	secrets := map[string]string{
		"cli-ledger-reader": "test-only-synthetic-hmac-secret-v1",
		"cli-order-router":  "test-only-synthetic-hmac-secret-v2",
		"cli-risk-auditor":  "test-only-synthetic-hmac-secret-v3",
		"cli-revoked-bot":   "test-only-synthetic-hmac-secret-v4",
	}
	for cid, sec := range secrets {
		sigKeys.AddHMACKey("hmac-"+cid, cid, []byte(sec))
	}

	polEngine, err := policy.NewEngine(ps, reg)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	eval := &gateway.Evaluator{
		Config:          cfg,
		PolicyEngine:    polEngine,
		TokenVerifier:   oidc.NewVerifier(cfg.OIDC, true, keyRing, oidc.NewMemoryTokenRevocationStore(), clock),
		RequestVerifier: signing.NewRequestVerifier(cfg.Signing, sigKeys, signing.NewMemoryNonceStore(1000), clock),
		RateLimiter:     ratelimit.NewTokenBucketLimiter(clock),
		CertRevocations: pki.NewMemoryCertRevocationStore(),
	}

	for i, tc := range fx.DecisionReferenceCases {
		t.Run(tc.ID, func(t *testing.T) {
			thumb := "thumb-" + tc.ClientID
			iss := cfg.OIDC.Issuer
			aud := cfg.OIDC.Audience
			exp := fixedTime.Add(5 * time.Minute)
			scopes := tc.Scopes
			if len(scopes) == 0 {
				scopes = []string{"accounts:read"}
			}

			switch tc.TokenMutation {
			case "expired":
				exp = fixedTime.Add(-2 * time.Minute)
			case "wrong_audience":
				aud = "https://other-service.finsec.local"
			case "wrong_issuer":
				iss = "https://untrusted-idp.finsec.local"
			}

			token, err := issuer.MintToken(oidc.MintParams{
				Issuer:         iss,
				Subject:        tc.ClientID,
				Audience:       aud,
				JWTID:          "jti-" + tc.ID,
				Scopes:         scopes,
				CertThumbprint: thumb,
				IssuedAt:       fixedTime,
				NotBefore:      fixedTime.Add(-10 * time.Second),
				ExpiresAt:      exp,
			})
			if err != nil {
				t.Fatalf("mint token: %v", err)
			}

			switch tc.TokenMutation {
			case "forged_signature":
				parts := strings.Split(token, ".")
				// Flip bytes in signature segment to simulate forged signature.
				sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sigBytes[0] ^= 0xff
				sigBytes[1] ^= 0xaa
				token = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
			case "alg_none":
				noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"ref-oidc-k1"}`))
				parts := strings.Split(token, ".")
				token = noneHdr + "." + parts[1] + "."
			}

			body := []byte("")
			if tc.Method == "POST" {
				body = []byte(`{"account_id":"ACC-1001","symbol":"SIM-AAPL","side":"BUY","qty":10,"limit_price":150.25}`)
			}
			keyID := "hmac-" + tc.ClientID
			nonce := tc.ID + "-nonce"
			ts := fixedTime.Format(time.RFC3339)
			sig, err := signing.SignRequest("HMAC-SHA256", keyID, ts, nonce, tc.Method, tc.Path, tc.RawQuery, body, nil, []byte(secrets[tc.ClientID]))
			if err != nil {
				t.Fatalf("sign request: %v", err)
			}

			env := domain.RequestEnvelope{
				RequestID:  tc.ID,
				Method:     tc.Method,
				Path:       tc.Path,
				RawQuery:   tc.RawQuery,
				Body:       body,
				BearerAuth: token,
				PeerCert: domain.PeerCertInfo{
					Present:          true,
					CommonName:       tc.ClientID,
					SerialHex:        "00aa" + string(rune('0'+i)),
					ThumbprintSHA256: thumb,
				},
				Signature: domain.SignatureHeaders{
					Algorithm: "HMAC-SHA256",
					KeyID:     keyID,
					Timestamp: ts,
					Nonce:     nonce,
					Signature: sig,
				},
				ReceivedAt: fixedTime,
			}

			res := eval.Evaluate(env)
			if string(res.Decision) != tc.ExpectedDecision {
				t.Errorf("decision got %s, want %s (reason=%s msg=%s)", res.Decision, tc.ExpectedDecision, res.ReasonCode, res.Message)
			}
			if string(res.ReasonCode) != tc.ExpectedReason {
				t.Errorf("reason got %s, want %s (msg=%s)", res.ReasonCode, tc.ExpectedReason, res.Message)
			}
			if res.HTTPStatus != tc.ExpectedStatus {
				t.Errorf("status got %d, want %d", res.HTTPStatus, tc.ExpectedStatus)
			}
		})
	}
}

func TestES256TokenAndAlgorithmConfusionRejected(t *testing.T) {
	cfg, _, _ := loadTestConfig(t)
	clock := domain.NewFixedClock(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	kr := oidc.NewKeyRing()
	if _, err := kr.AddES256Key("es256-k1", nil, true, clock.Now()); err != nil {
		t.Fatalf("add es256 key: %v", err)
	}
	issuer := oidc.NewIssuer(kr)
	verifier := oidc.NewVerifier(cfg.OIDC, true, kr, oidc.NewMemoryTokenRevocationStore(), clock)

	tok, err := issuer.MintToken(oidc.MintParams{
		Issuer: cfg.OIDC.Issuer, Subject: "cli-ledger-reader", Audience: cfg.OIDC.Audience,
		JWTID: "jti-es256-1", Scopes: []string{"accounts:read"}, CertThumbprint: "thumb-1",
		IssuedAt: clock.Now(), NotBefore: clock.Now(), ExpiresAt: clock.Now().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("mint es256: %v", err)
	}
	claims, rc, err := verifier.Verify(tok, "thumb-1")
	if err != nil || rc != domain.ReasonAllowed || claims.Algorithm != "ES256" {
		t.Fatalf("expected valid ES256 verification, got err=%v rc=%s alg=%s", err, rc, claims.Algorithm)
	}

	// HS256 algorithm confusion attack must be rejected
	hsHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"es256-k1"}`))
	parts := strings.Split(tok, ".")
	hsTok := hsHdr + "." + parts[1] + "." + parts[2]
	_, rc, err = verifier.Verify(hsTok, "thumb-1")
	if err == nil || rc != domain.ReasonTokenAlgRejected {
		t.Fatalf("expected ERR_TOKEN_ALG_REJECTED for HS256 confusion, got err=%v rc=%s", err, rc)
	}
}
