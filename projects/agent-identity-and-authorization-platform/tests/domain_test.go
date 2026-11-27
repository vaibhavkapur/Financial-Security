package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/audit"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/enforcer"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

type testHarness struct {
	ctx          context.Context
	cfg          config.Config
	clock        *domain.FixedClock
	store        *store.SQLiteStore
	svc          *enforcer.PlatformService
	authKey      crypto.KeyPair
	delegatorKey crypto.KeyPair
	agentKey     crypto.KeyPair
	subAgentKey  crypto.KeyPair
}

func newTestHarness(t *testing.T, dsn string) *testHarness {
	t.Helper()
	ctx := context.Background()
	cfg := config.DefaultConfig()
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(baseTime)

	if dsn == "" {
		dsn = ":memory:"
	}
	st, err := store.NewSQLiteStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	authKey := crypto.DeterministicFixtureKeyPair("auth-test-k1", "test-authority")
	delKey := crypto.DeterministicFixtureKeyPair("del-alice", "test-alice")
	agtKey := crypto.DeterministicFixtureKeyPair("agt-01", "test-agent-01")
	subKey := crypto.DeterministicFixtureKeyPair("agt-02", "test-agent-02")

	svc, err := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	if err != nil {
		t.Fatalf("NewPlatformService: %v", err)
	}

	principals := []domain.Principal{
		{PrincipalID: "delegator.treasury.alice", PrincipalType: domain.PrincipalHumanDelegator, DisplayName: "Alice Mock", TenantID: "mock-tenant-alpha", PublicKeyB64: delKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.rebalancer.01", PrincipalType: domain.PrincipalAgent, DisplayName: "Agent 01", TenantID: "mock-tenant-alpha", PublicKeyB64: agtKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.subexec.02", PrincipalType: domain.PrincipalAgent, DisplayName: "Agent 02", TenantID: "mock-tenant-alpha", PublicKeyB64: subKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
	}
	for _, p := range principals {
		if err := svc.RegisterPrincipal(ctx, p); err != nil {
			t.Fatalf("RegisterPrincipal %s: %v", p.PrincipalID, err)
		}
	}

	return &testHarness{
		ctx:          ctx,
		cfg:          cfg,
		clock:        clock,
		store:        st,
		svc:          svc,
		authKey:      authKey,
		delegatorKey: delKey,
		agentKey:     agtKey,
		subAgentKey:  subKey,
	}
}

func (h *testHarness) issueDefaultRootGrant(t *testing.T) domain.IssuedGrant {
	t.Helper()
	g, err := h.svc.IssueRootGrant(h.ctx, domain.GrantRequest{
		GrantID:               "grt-test-root-01",
		CanDelegate:           true,
		DelegatorID:           "delegator.treasury.alice",
		ActorID:               "agent.rebalancer.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-100*"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         50000,
			MaxCumulativeMinor:        100000,
			RequireApprovalAboveMinor: 15000,
		},
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("IssueRootGrant: %v", err)
	}
	return g
}

func TestCanonicalDigestOracleAndDeterminism(t *testing.T) {
	a1 := domain.ActionPayload{
		ActionID:       "act-oracle-01",
		ActionType:     "payment.initiate",
		Audience:       "mock-treasury-api",
		TenantID:       "mock-tenant-alpha",
		ResourceID:     "mock-acct-1001",
		CounterpartyID: "mock-cp-clearing-a",
		AmountMinor:    10000,
		Currency:       "USD",
		Metadata:       map[string]string{"b": "2", "a": "1"},
	}
	a2 := a1
	a2.Metadata = map[string]string{"a": "1", "b": "2"}

	// Independent oracle calculation over exact documented canonical JSON format.
	expectedRaw := `aiap.action.v1:{"action_id":"act-oracle-01","action_type":"payment.initiate","amount_minor":10000,"audience":"mock-treasury-api","counterparty_id":"mock-cp-clearing-a","currency":"USD","metadata":[{"k":"a","v":"1"},{"k":"b","v":"2"}],"resource_id":"mock-acct-1001","tenant_id":"mock-tenant-alpha"}`
	oracleSum := sha256.Sum256([]byte(expectedRaw))
	oracleHex := hex.EncodeToString(oracleSum[:])

	d1 := domain.ComputeActionDigest(a1)
	d2 := domain.ComputeActionDigest(a2)
	if d1 != d2 {
		t.Fatalf("digest not invariant to map iteration order: %s != %s", d1, d2)
	}
	if d1 != oracleHex {
		t.Fatalf("digest mismatch vs independent oracle:\ngot:  %s\nwant: %s\nraw:  %s", d1, oracleHex, string(domain.CanonicalActionBytes(a1)))
	}

	// 1 minor unit alteration must change the digest.
	a3 := a1
	a3.AmountMinor = 10001
	if domain.ComputeActionDigest(a3) == d1 {
		t.Fatalf("1-cent alteration produced identical digest")
	}
}

func TestDomainCore_ExpiredGrant_AudienceMismatch_AlteredAmount(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	// 1. Audience mismatch
	decAud, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-aud-mismatch", ActionType: "payment.initiate", Audience: "mock-settlement-engine",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 5000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize audience mismatch: %v", err)
	}
	if decAud.Decision != domain.DecisionDeny || decAud.ReasonCode != domain.ReasonAudienceMismatch {
		t.Fatalf("expected DENY/ERR_AUDIENCE_MISMATCH, got %s/%s", decAud.Decision, decAud.ReasonCode)
	}

	// 2. Altered amount (+1 minor unit after delegator signed exact-action approval)
	approvedAction := domain.ActionPayload{
		ActionID: "act-amt-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
	}
	appRec, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-amt-01",
		GrantID:      root.Grant.GrantID,
		ActorID:      root.Grant.ActorID,
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(approvedAction),
		Nonce:        "nonce-amt-01",
		IssuedAtUTC:  h.clock.Now(),
		ExpiresAtUTC: h.clock.Now().Add(2 * time.Minute),
	}, h.delegatorKey.PrivateKey)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	altered := approvedAction
	altered.AmountMinor = 25001
	decAlt, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action:     altered,
		Approval:   &appRec,
	})
	if err != nil {
		t.Fatalf("Authorize altered amount: %v", err)
	}
	if decAlt.Decision != domain.DecisionDeny || decAlt.ReasonCode != domain.ReasonApprovalPayloadMismatch {
		t.Fatalf("expected DENY/ERR_APPROVAL_PAYLOAD_MISMATCH, got %s/%s", decAlt.Decision, decAlt.ReasonCode)
	}

	// 3. Expired grant (advance clock to exact expiry boundary t+300s)
	h.clock.Advance(300 * time.Second)
	decExp, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-exp-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize expired grant: %v", err)
	}
	if decExp.Decision != domain.DecisionDeny || decExp.ReasonCode != domain.ReasonGrantExpired {
		t.Fatalf("expected DENY/ERR_GRANT_EXPIRED, got %s/%s", decExp.Decision, decExp.ReasonCode)
	}
}

func TestJWTAlgorithmDowngradeRejected(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	// alg: none attack
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": h.cfg.IssuerID, "sub": "agent.rebalancer.01", "jti": root.Grant.GrantID,
		"exp": h.clock.Now().Add(5 * time.Minute).Unix(), "iat": h.clock.Now().Unix(),
	})
	noneStr, err := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none jwt: %v", err)
	}
	decNone, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: noneStr,
		Action: domain.ActionPayload{
			ActionID: "act-none", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize alg=none: %v", err)
	}
	if decNone.Decision != domain.DecisionDeny || decNone.ReasonCode != domain.ReasonTokenInvalidAlg {
		t.Fatalf("expected DENY/ERR_TOKEN_INVALID_ALG for alg=none, got %s/%s", decNone.Decision, decNone.ReasonCode)
	}
}

func TestBoundaryAndInvalidFixtures(t *testing.T) {
	raw, err := os.ReadFile("../data/fixtures/boundary_and_invalid.json")
	if err != nil {
		t.Fatalf("read boundary fixture: %v", err)
	}
	var fx struct {
		Cases []struct {
			ID                 string                 `json:"id"`
			Description        string                 `json:"description"`
			AmountMinor        int64                  `json:"amount_minor"`
			Currency           string                 `json:"currency"`
			ActionType         string                 `json:"action_type"`
			Audience           string                 `json:"audience"`
			ResourceID         string                 `json:"resource_id"`
			CounterpartyID     string                 `json:"counterparty_id"`
			ExpectedDecision   domain.DecisionOutcome `json:"expected_decision"`
			ExpectedReasonCode domain.ReasonCode      `json:"expected_reason_code"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal boundary fixture: %v", err)
	}

	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	for _, tc := range fx.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			dec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
				GrantToken: root.Token,
				Action: domain.ActionPayload{
					ActionID:       "act-" + tc.ID,
					ActionType:     tc.ActionType,
					Audience:       tc.Audience,
					TenantID:       "mock-tenant-alpha",
					ResourceID:     tc.ResourceID,
					CounterpartyID: tc.CounterpartyID,
					AmountMinor:    tc.AmountMinor,
					Currency:       tc.Currency,
				},
			})
			if err != nil {
				t.Fatalf("Authorize %s: %v", tc.ID, err)
			}
			if dec.Decision != tc.ExpectedDecision || dec.ReasonCode != tc.ExpectedReasonCode {
				t.Fatalf("%s (%s): got %s/%s, want %s/%s", tc.ID, tc.Description, dec.Decision, dec.ReasonCode, tc.ExpectedDecision, tc.ExpectedReasonCode)
			}
		})
	}
}

func TestTelemetryRedactionPreservesReplay(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	action := domain.ActionPayload{
		ActionID: "act-redact-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
		Metadata: map[string]string{
			"memo_pii":   "SYNTHETIC-SECRET-PII-999",
			"api_key":    "SYNTHETIC-KEY-XYZ",
			"cost_center": "desk-alpha",
		},
	}
	appRec, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-redact-01",
		GrantID:      root.Grant.GrantID,
		ActorID:      root.Grant.ActorID,
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(action),
		Nonce:        "nonce-redact-01",
		IssuedAtUTC:  h.clock.Now(),
		ExpiresAtUTC: h.clock.Now().Add(2 * time.Minute),
	}, h.delegatorKey.PrivateKey)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}

	dec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action:     action,
		Approval:   &appRec,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if dec.Decision != domain.DecisionAllow {
		t.Fatalf("expected ALLOW, got %s/%s", dec.Decision, dec.ReasonCode)
	}

	events, err := h.store.ListAuditEvents(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	for _, ev := range events {
		if strings.Contains(ev.RedactedPayloadJSON, "SYNTHETIC-SECRET-PII-999") ||
			strings.Contains(ev.RedactedPayloadJSON, "SYNTHETIC-KEY-XYZ") ||
			strings.Contains(ev.ReplayEnvelopeJSON, "SYNTHETIC-SECRET-PII-999") ||
			strings.Contains(ev.ReplayEnvelopeJSON, "SYNTHETIC-KEY-XYZ") {
			t.Fatalf("sensitive metadata leaked into audit log event %d", ev.SequenceNo)
		}
	}

	replay := audit.ReplayAuditLog(events)
	if !replay.Passed || !replay.ChainValid {
		t.Fatalf("audit replay failed after redaction: %+v", replay)
	}
}
