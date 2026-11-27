package containment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Simulator manages reviewed, simulation-only containment proposals and a hash-chained reviewer audit log.
// Architectural invariant: automatic or live containment is permanently disabled.
type Simulator struct {
	authorizedReviewers map[string]bool
	dualControlSevs     map[contracts.Severity]bool
	proposals           map[string]*contracts.ContainmentProposal
	caseActors          map[string]string
	auditLog            []contracts.AuditRecord
}

func NewSimulator(policy contracts.SecurityPolicy) (*Simulator, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	reviewers := make(map[string]bool, len(policy.AuthorizedReviewers))
	for _, r := range policy.AuthorizedReviewers {
		reviewers[strings.ToLower(strings.TrimSpace(r))] = true
	}
	dual := make(map[contracts.Severity]bool, len(policy.DualControlSeverities))
	for _, s := range policy.DualControlSeverities {
		dual[s] = true
	}
	return &Simulator{
		authorizedReviewers: reviewers,
		dualControlSevs:     dual,
		proposals:           make(map[string]*contracts.ContainmentProposal),
		caseActors:          make(map[string]string),
		auditLog:            make([]contracts.AuditRecord, 0),
	}, nil
}

// ExecuteLive always fails closed: live containment is strictly out of scope for this defensive lab.
func (s *Simulator) ExecuteLive(proposalID string) error {
	return fmt.Errorf("%w: proposal %s cannot be executed against live trading infrastructure", contracts.ErrLiveContainmentProhibited, proposalID)
}

// ProposeFromCase generates reviewed containment simulation proposals for a correlated case.
func (s *Simulator) ProposeFromCase(c contracts.Case, requestedBy string, now time.Time) []contracts.ContainmentProposal {
	s.caseActors[c.CaseID] = strings.ToLower(strings.TrimSpace(c.PrimaryActor))
	required := 1
	if s.dualControlSevs[c.Severity] {
		required = 2
	}

	actions := c.RecommendedActions
	if len(actions) == 0 {
		actions = []string{"simulate_triage_review"}
	}

	out := make([]contracts.ContainmentProposal, 0, len(actions))
	for _, act := range actions {
		target := selectTarget(act, c)
		pid := contracts.StableID("PROP", c.CaseID, act, target)
		prop := &contracts.ContainmentProposal{
			ProposalID:        pid,
			CaseID:            c.CaseID,
			ActionType:        act,
			Target:            target,
			ExecutionMode:     contracts.ContainmentModeSimulationOnly,
			LiveExecuted:      false,
			Severity:          c.Severity,
			RequestedBy:       strings.ToLower(strings.TrimSpace(requestedBy)),
			RequiredApprovals: required,
			Status:            "pending_review",
			Approvals:         []contracts.ReviewerApproval{},
			BlastRadius:       buildBlastRadius(act, c),
			RollbackPlan:      buildRollbackPlan(act, target),
			SimulatedDiff:     map[string]string{},
			CreatedAt:         now.UTC(),
		}
		s.proposals[pid] = prop
		out = append(out, *prop)
	}
	return out
}

// ReviewProposal records an authorized human reviewer decision with separation-of-duties and dual-control checks.
func (s *Simulator) ReviewProposal(proposalID, reviewer, decision, rationale string, now time.Time) (contracts.ContainmentProposal, error) {
	prop, ok := s.proposals[proposalID]
	if !ok {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: unknown proposal_id %s", contracts.ErrValidationFailed, proposalID)
	}
	revNorm := strings.ToLower(strings.TrimSpace(reviewer))
	if !s.authorizedReviewers[revNorm] {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: %s", contracts.ErrUnauthorizedReviewer, reviewer)
	}
	if revNorm == prop.RequestedBy || revNorm == s.caseActors[prop.CaseID] {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: reviewer %s cannot review proposal %s", contracts.ErrSelfApprovalProhibited, reviewer, proposalID)
	}
	decNorm := strings.ToLower(strings.TrimSpace(decision))
	if decNorm != "approve" && decNorm != "reject" {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: decision must be 'approve' or 'reject', got %q", contracts.ErrValidationFailed, decision)
	}
	if strings.TrimSpace(rationale) == "" {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: reviewer rationale is required", contracts.ErrValidationFailed)
	}
	for _, existing := range prop.Approvals {
		if existing.Reviewer == revNorm {
			return contracts.ContainmentProposal{}, fmt.Errorf("%w: reviewer %s already reviewed proposal %s", contracts.ErrValidationFailed, reviewer, proposalID)
		}
	}

	approval := contracts.ReviewerApproval{
		Reviewer:  revNorm,
		Decision:  decNorm,
		Rationale: strings.TrimSpace(rationale),
		Timestamp: now.UTC(),
	}
	prop.Approvals = append(prop.Approvals, approval)

	if decNorm == "reject" {
		prop.Status = "rejected"
	} else {
		approveCount := 0
		for _, a := range prop.Approvals {
			if a.Decision == "approve" {
				approveCount++
			}
		}
		if approveCount >= prop.RequiredApprovals {
			prop.Status = "approved_simulation"
		}
	}

	s.appendAudit(revNorm, "review_containment_proposal", proposalID, decNorm, approval.Rationale, now.UTC())
	return *prop, nil
}

// SimulateApproved runs a dry-run containment simulation strictly after required reviewer approvals are met.
func (s *Simulator) SimulateApproved(proposalID, operator string, now time.Time) (contracts.ContainmentProposal, error) {
	prop, ok := s.proposals[proposalID]
	if !ok {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: unknown proposal_id %s", contracts.ErrValidationFailed, proposalID)
	}
	if prop.Status != "approved_simulation" {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: proposal %s status is %q (requires 'approved_simulation')", contracts.ErrValidationFailed, proposalID, prop.Status)
	}
	opNorm := strings.ToLower(strings.TrimSpace(operator))
	if !s.authorizedReviewers[opNorm] {
		return contracts.ContainmentProposal{}, fmt.Errorf("%w: operator %s is not authorized", contracts.ErrUnauthorizedReviewer, operator)
	}

	prop.SimulatedDiff = buildSimulatedDiff(prop.ActionType, prop.Target)
	prop.Status = "simulated"
	prop.LiveExecuted = false // Hard invariant: never execute live
	s.appendAudit(opNorm, "execute_containment_simulation", proposalID, "simulated_dry_run", "Executed offline simulation only; zero live trading mutations", now.UTC())
	return *prop, nil
}

// RecordSuppressionAudit logs an auditable record whenever a false-positive suppression fires.
func (s *Simulator) RecordSuppressionAudit(suppressionID, alertID, approvedBy, rationale string, ts time.Time) {
	s.appendAudit(
		strings.ToLower(strings.TrimSpace(approvedBy)),
		"alert_suppression_applied",
		fmt.Sprintf("%s:%s", suppressionID, alertID),
		"suppressed",
		rationale,
		ts.UTC(),
	)
}

// Proposals returns all tracked proposals in deterministic ID order.
func (s *Simulator) Proposals() []contracts.ContainmentProposal {
	out := make([]contracts.ContainmentProposal, 0, len(s.proposals))
	for _, p := range s.proposals {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProposalID < out[j].ProposalID })
	return out
}

// AuditLog returns a copy of the tamper-evident hash-chained audit records.
func (s *Simulator) AuditLog() []contracts.AuditRecord {
	out := make([]contracts.AuditRecord, len(s.auditLog))
	copy(out, s.auditLog)
	return out
}

// VerifyAuditChain checks the cryptographic linkage of every record in the reviewer audit log.
func VerifyAuditChain(records []contracts.AuditRecord) error {
	prev := genesisHash
	for i, rec := range records {
		expectedSeq := int64(i + 1)
		if rec.SequenceNum != expectedSeq {
			return fmt.Errorf("%w: record %d expected sequence %d, got %d", contracts.ErrAuditChainTampered, i, expectedSeq, rec.SequenceNum)
		}
		if rec.PrevHash != prev {
			return fmt.Errorf("%w: record %d prev_hash mismatch", contracts.ErrAuditChainTampered, i)
		}
		expectedHash := computeAuditHash(rec)
		if rec.RecordHash != expectedHash {
			return fmt.Errorf("%w: record %d hash mismatch", contracts.ErrAuditChainTampered, i)
		}
		prev = rec.RecordHash
	}
	return nil
}

func (s *Simulator) appendAudit(reviewer, action, targetID, decision, rationale string, ts time.Time) {
	prev := genesisHash
	if n := len(s.auditLog); n > 0 {
		prev = s.auditLog[n-1].RecordHash
	}
	seq := int64(len(s.auditLog) + 1)
	rec := contracts.AuditRecord{
		SequenceNum: seq,
		RecordID:    contracts.StableID("AUD", fmt.Sprintf("%d", seq), reviewer, action, targetID, decision),
		Timestamp:   ts,
		Reviewer:    reviewer,
		Action:      action,
		TargetID:    targetID,
		Decision:    decision,
		Rationale:   rationale,
		PrevHash:    prev,
	}
	rec.RecordHash = computeAuditHash(rec)
	s.auditLog = append(s.auditLog, rec)
}

func computeAuditHash(rec contracts.AuditRecord) string {
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s",
		rec.SequenceNum,
		rec.RecordID,
		rec.Timestamp.UTC().Format(time.RFC3339Nano),
		rec.Reviewer,
		rec.Action,
		rec.TargetID,
		rec.Decision,
		rec.Rationale,
		rec.PrevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func selectTarget(action string, c contracts.Case) string {
	switch action {
	case "simulate_revoke_session", "simulate_freeze_trading_credentials":
		return "actor:" + c.PrimaryActor
	case "simulate_quarantine_host":
		if len(c.AffectedHosts) > 0 {
			return "host:" + c.AffectedHosts[0]
		}
	case "simulate_revert_config_diff":
		if len(c.AffectedServices) > 0 {
			return "service:" + c.AffectedServices[0]
		}
	}
	return "case:" + c.CaseID
}

func buildBlastRadius(action string, c contracts.Case) []string {
	br := []string{"simulation_only: zero live trading impact"}
	for _, svc := range c.AffectedServices {
		br = append(br, "simulated_service_scope:"+svc)
	}
	for _, h := range c.AffectedHosts {
		br = append(br, "simulated_host_scope:"+h)
	}
	br = append(br, "action:"+action)
	return br
}

func buildRollbackPlan(action, target string) string {
	switch action {
	case "simulate_revoke_session":
		return fmt.Sprintf("Simulation rollback: restore synthetic session state for %s via IAM fixture snapshot", target)
	case "simulate_revert_config_diff":
		return fmt.Sprintf("Simulation rollback: re-apply last signed baseline config manifest for %s", target)
	case "simulate_quarantine_host":
		return fmt.Sprintf("Simulation rollback: remove simulated network quarantine ACL on %s after forensic capture", target)
	case "simulate_freeze_trading_credentials":
		return fmt.Sprintf("Simulation rollback: issue fresh synthetic trading credentials for %s after dual-control sign-off", target)
	default:
		return fmt.Sprintf("Simulation rollback: no live mutations performed for %s", target)
	}
}

func buildSimulatedDiff(action, target string) map[string]string {
	return map[string]string{
		"mode":            contracts.ContainmentModeSimulationOnly,
		"target":          target,
		"action":          action,
		"before_state":    "active_synthetic_state",
		"after_state":     "contained_synthetic_state_dry_run",
		"live_side_effect": "none",
	}
}
