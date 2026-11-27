package tests

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/containment"
	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/pipeline"
)

// Required boundary/failure scenario: False-positive suppression and reviewer audit
func TestBoundaryFalsePositiveSuppressionAndReviewerAudit(t *testing.T) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig: %v", err)
	}
	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/suppression_and_reviewer_audit.jsonl")
	if err != nil {
		t.Fatalf("RunFromJSONL: %v", err)
	}

	// Verify sup-001 (before expiry) is suppressed & audited, while sup-005 (after expiry) & sup-006 (role_grant) remain active!
	if res.Report.Metrics.AlertsSuppressed != 1 {
		t.Fatalf("expected 1 suppressed alert, got %d", res.Report.Metrics.AlertsSuppressed)
	}
	foundSup001 := false
	foundPostExpiry := false
	foundRoleGrant := false
	for _, a := range res.Report.Alerts {
		switch {
		case a.RuleID == "TISM-SIGMA-003" && a.SourceEventIDs[0] == "sup-001":
			if !a.Suppressed || a.SuppressionID != "SUP-2026-001" {
				t.Fatalf("expected sup-001 suppressed by SUP-2026-001, got %+v", a)
			}
			foundSup001 = true
		case a.RuleID == "TISM-SIGMA-003" && a.SourceEventIDs[0] == "sup-005":
			if a.Suppressed {
				t.Fatalf("expected sup-005 after expiry NOT to be suppressed")
			}
			foundPostExpiry = true
		case a.RuleID == "TISM-SIGMA-002" && a.SourceEventIDs[0] == "sup-006":
			if !a.Suppressed {
				foundRoleGrant = true
			}
		}
	}
	if !foundSup001 || !foundPostExpiry || !foundRoleGrant {
		t.Fatalf("missing expected suppression/expiry/escalation alerts: sup001=%v postExpiry=%v roleGrant=%v", foundSup001, foundPostExpiry, foundRoleGrant)
	}

	// Verify suppression audit record was automatically added to hash-chained reviewer audit log
	if len(res.Report.ReviewerAuditLog) == 0 {
		t.Fatalf("expected suppression audit entry in reviewer_audit_log")
	}

	// Verify reviewer workflow on critical case proposal (dual control + no self-approval + no live execution)
	if len(res.Report.ContainmentProposals) == 0 {
		t.Fatalf("expected containment proposals for critical post-expiry escalation case")
	}
	prop := res.Report.ContainmentProposals[0]
	if err := p.Simulator.ExecuteLive(prop.ProposalID); !errors.Is(err, contracts.ErrLiveContainmentProhibited) {
		t.Fatalf("expected ErrLiveContainmentProhibited, got %v", err)
	}
	if _, err := p.Simulator.ReviewProposal(prop.ProposalID, "unlisted-user", "approve", "bad", fixedClock()); !errors.Is(err, contracts.ErrUnauthorizedReviewer) {
		t.Fatalf("expected ErrUnauthorizedReviewer, got %v", err)
	}
	if _, err := p.Simulator.ReviewProposal(prop.ProposalID, "sec-reviewer-alice", "approve", "Verified post-expiry escalation", fixedClock().Add(time.Minute)); err != nil {
		t.Fatalf("first approval failed: %v", err)
	}
	if prop.RequiredApprovals == 2 {
		if _, err := p.Simulator.ReviewProposal(prop.ProposalID, "sec-reviewer-bob", "approve", "Second reviewer dual-control sign-off", fixedClock().Add(2*time.Minute)); err != nil {
			t.Fatalf("second approval failed: %v", err)
		}
	}
	simProp, err := p.Simulator.SimulateApproved(prop.ProposalID, "soc-lead-carol", fixedClock().Add(3*time.Minute))
	if err != nil {
		t.Fatalf("SimulateApproved failed: %v", err)
	}
	if simProp.LiveExecuted {
		t.Fatalf("containment must NEVER execute live")
	}

	// Verify complete hash chain (suppression + review approvals + simulation record)
	auditLog := p.Simulator.AuditLog()
	if err := containment.VerifyAuditChain(auditLog); err != nil {
		t.Fatalf("audit chain verification failed: %v", err)
	}
}

// Required operational review tests: missing config, invalid config, live-containment config, unsupported inputs
func TestOperationalFailureModesNoSilentSuccess(t *testing.T) {
	// 1. Missing configuration
	if _, err := pipeline.LoadFromConfig("../config/does_not_exist.json", nil, fixedClock); !errors.Is(err, contracts.ErrMissingConfig) {
		t.Fatalf("expected ErrMissingConfig for missing config file, got %v", err)
	}

	// 2. Attempting to enable live containment in config must fail closed
	tmpDir := t.TempDir()
	badCfgPath := filepath.Join(tmpDir, "bad_live_config.json")
	badCfg := `{"schema_version":"1.0.0","containment_mode":"live","live_containment_enabled":true,"correlation_window_seconds":900,"telemetry_gap_threshold_seconds":300}`
	if err := os.WriteFile(badCfgPath, []byte(badCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.LoadFromConfig(badCfgPath, nil, fixedClock); !errors.Is(err, contracts.ErrLiveContainmentProhibited) {
		t.Fatalf("expected ErrLiveContainmentProhibited for live config, got %v", err)
	}

	// 3. Invalid & unsupported input events must be surfaced explicitly in ValidationErrors (no silent drop)
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/invalid/invalid_events.jsonl")
	if err != nil {
		t.Fatalf("expected structured validation errors rather than crash, got err: %v", err)
	}
	if res.Report.Metrics.EventsInvalid != 5 || len(res.Report.ValidationErrors) != 5 {
		t.Fatalf("expected 5 explicit validation errors for invalid_events.jsonl, got metrics=%d errs=%d",
			res.Report.Metrics.EventsInvalid, len(res.Report.ValidationErrors))
	}
	if res.Report.Metrics.EventsNormalized != 0 {
		t.Fatalf("expected 0 normalized events from invalid fixture, got %d", res.Report.Metrics.EventsNormalized)
	}
}
