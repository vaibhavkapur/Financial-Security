package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/audit"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

func TestAdversarial_DelegationEscalationSuiteAndReproducibility(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	seed := cfg.Evaluation.RandomSeed

	rep1, err := audit.RunAdversarialSuite(ctx, cfg, seed)
	if err != nil {
		t.Fatalf("RunAdversarialSuite run 1: %v", err)
	}
	if !rep1.Passed {
		b, _ := json.MarshalIndent(rep1, "", "  ")
		t.Fatalf("adversarial suite failed:\n%s", string(b))
	}
	if rep1.TotalCases < 16 || rep1.PassedCases != rep1.TotalCases {
		t.Fatalf("expected all >=16 adversarial cases to pass, got %d/%d", rep1.PassedCases, rep1.TotalCases)
	}
	if rep1.FuzzMutationsBlocked != rep1.FuzzMutationsRun || rep1.FuzzMutationsRun == 0 {
		t.Fatalf("expected 100%% fuzz mutation block rate, got %d/%d", rep1.FuzzMutationsBlocked, rep1.FuzzMutationsRun)
	}
	if !rep1.ReplayVerified {
		t.Fatalf("expected adversarial suite audit replay to pass")
	}

	// Reproducibility check: identical seed and config must produce identical logical outcomes.
	rep2, err := audit.RunAdversarialSuite(ctx, cfg, seed)
	if err != nil {
		t.Fatalf("RunAdversarialSuite run 2: %v", err)
	}
	b1, _ := json.Marshal(rep1)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("adversarial suite not reproducible across fixed-seed runs:\nrun1=%s\nrun2=%s", string(b1), string(b2))
	}
}

func TestAdversarial_AuditTamperDetection(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	// Generate a DENY decision (high-value without approval) and an ALLOW decision.
	_, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-tamper-deny", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 25000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	_, err = h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-tamper-allow", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 5000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Verify clean replay before tampering.
	events, err := h.store.ListAuditEvents(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	clean := audit.ReplayAuditLog(events)
	if !clean.Passed || !clean.ChainValid {
		t.Fatalf("expected clean replay before tampering, got %+v", clean)
	}

	// Simulate malicious direct DB tampering altering a DENY to ALLOW.
	if _, err := h.store.DB().ExecContext(h.ctx, `UPDATE audit_events SET decision = 'ALLOW' WHERE decision = 'DENY'`); err != nil {
		t.Fatalf("tamper SQL: %v", err)
	}

	tamperedEvents, err := h.store.ListAuditEvents(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents tampered: %v", err)
	}
	detected := audit.ReplayAuditLog(tamperedEvents)
	if detected.ChainValid || detected.Passed || len(detected.Mismatches) == 0 {
		t.Fatalf("expected tamper detection failure, got %+v", detected)
	}
}

func TestAdversarial_SubDelegationCumulativeCapChainEnforcement(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t) // max_cumulative_minor = 100000

	// Spend 80000 on root grant directly (in two 40000 payments with approvals? Use 6x 15000 = 90000 below approval threshold!).
	for i := 0; i < 6; i++ {
		d, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
			GrantToken: root.Token,
			Action: domain.ActionPayload{
				ActionID: "act-burn-" + string(rune('a'+i)), ActionType: "payment.initiate", Audience: "mock-treasury-api",
				TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
				AmountMinor: 15000, Currency: "USD",
			},
		})
		if err != nil || d.Decision != domain.DecisionAllow {
			t.Fatalf("burn payment %d expected ALLOW, got %+v err=%v", i, d, err)
		}
	}

	// Root now has only 10000 remaining. Attempting to sub-delegate 20000 cumulative cap must fail as escalation!
	_, err := h.svc.IssueSubDelegatedGrant(h.ctx, domain.GrantRequest{
		GrantID:               "grt-esc-remaining",
		ParentGrantID:         root.Grant.GrantID,
		DelegatorID:           "agent.rebalancer.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         10000,
			MaxCumulativeMinor:        20000,
			RequireApprovalAboveMinor: 10000,
		},
		TTLSeconds: 120,
	})
	var de *domain.DomainError
	if !errors.As(err, &de) || de.Code != domain.ReasonDelegationEscalation {
		t.Fatalf("expected ERR_DELEGATION_ESCALATION when sub-delegating beyond parent remaining cap, got %v", err)
	}
}
