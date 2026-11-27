package containment

import (
	"errors"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

func TestContainmentSimulationDualControlAndAuditChain(t *testing.T) {
	policy, err := contracts.LoadJSONFile[contracts.SecurityPolicy]("../../config/policy.json")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	sim, err := NewSimulator(policy)
	if err != nil {
		t.Fatalf("NewSimulator: %v", err)
	}

	now := time.Date(2026, 6, 1, 11, 0, 0, 0, time.UTC)
	c := contracts.Case{
		CaseID:             "CASE-CRIT-01",
		Severity:           contracts.SeverityCritical,
		PrimaryActor:       "dev-rogue-1",
		AffectedServices:   []string{"risk-engine"},
		AffectedHosts:      []string{"trd-rsk-01"},
		RecommendedActions: []string{"simulate_freeze_trading_credentials"},
	}

	props := sim.ProposeFromCase(c, "soc-analyst-auto", now)
	if len(props) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props))
	}
	pid := props[0].ProposalID
	if props[0].RequiredApprovals != 2 {
		t.Fatalf("expected dual control (2 approvals) for critical case, got %d", props[0].RequiredApprovals)
	}

	// Hard guard: live execution must ALWAYS fail
	if err := sim.ExecuteLive(pid); !errors.Is(err, contracts.ErrLiveContainmentProhibited) {
		t.Fatalf("expected ErrLiveContainmentProhibited, got %v", err)
	}

	// Unauthorized reviewer rejected
	if _, err := sim.ReviewProposal(pid, "random-trader", "approve", "looks ok", now); !errors.Is(err, contracts.ErrUnauthorizedReviewer) {
		t.Fatalf("expected ErrUnauthorizedReviewer, got %v", err)
	}

	// Cannot simulate before 2 approvals
	if _, err := sim.SimulateApproved(pid, "sec-reviewer-alice", now); err == nil {
		t.Fatalf("expected error simulating unapproved proposal")
	}

	// First authorized approval -> still pending_review (dual control)
	p1, err := sim.ReviewProposal(pid, "sec-reviewer-alice", "approve", "Verified evidence chain", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("first review failed: %v", err)
	}
	if p1.Status != "pending_review" {
		t.Fatalf("expected pending_review after 1 of 2 approvals, got %s", p1.Status)
	}

	// Second authorized approval -> approved_simulation
	p2, err := sim.ReviewProposal(pid, "sec-reviewer-bob", "approve", "Concur with freeze simulation", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second review failed: %v", err)
	}
	if p2.Status != "approved_simulation" {
		t.Fatalf("expected approved_simulation after 2 approvals, got %s", p2.Status)
	}

	// Run simulation
	p3, err := sim.SimulateApproved(pid, "soc-lead-carol", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("SimulateApproved failed: %v", err)
	}
	if p3.Status != "simulated" || p3.LiveExecuted {
		t.Fatalf("expected simulated status with LiveExecuted=false, got status=%s live=%v", p3.Status, p3.LiveExecuted)
	}

	// Verify audit chain integrity and tamper detection
	log := sim.AuditLog()
	if err := VerifyAuditChain(log); err != nil {
		t.Fatalf("expected valid audit chain, got %v", err)
	}
	tampered := append([]contracts.AuditRecord{}, log...)
	tampered[0].Rationale = "tampered rationale"
	if err := VerifyAuditChain(tampered); !errors.Is(err, contracts.ErrAuditChainTampered) {
		t.Fatalf("expected ErrAuditChainTampered on modified log, got %v", err)
	}
}

func TestSelfApprovalProhibited(t *testing.T) {
	policy, _ := contracts.LoadJSONFile[contracts.SecurityPolicy]("../../config/policy.json")
	sim, _ := NewSimulator(policy)
	now := time.Date(2026, 6, 1, 11, 0, 0, 0, time.UTC)

	c := contracts.Case{
		CaseID:             "CASE-HIGH-01",
		Severity:           contracts.SeverityHigh,
		PrimaryActor:       "ops-1",
		AffectedServices:   []string{"order-router"},
		AffectedHosts:      []string{"trd-ord-01"},
		RecommendedActions: []string{"simulate_revoke_session"},
	}
	props := sim.ProposeFromCase(c, "sec-reviewer-alice", now)
	if _, err := sim.ReviewProposal(props[0].ProposalID, "sec-reviewer-alice", "approve", "self-approve attempt", now); !errors.Is(err, contracts.ErrSelfApprovalProhibited) {
		t.Fatalf("expected ErrSelfApprovalProhibited, got %v", err)
	}
}
