package audit

import (
	"encoding/json"
	"fmt"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

// ReplayMismatch records a discrepancy found during deterministic audit replay.
type ReplayMismatch struct {
	SequenceNo       int64                  `json:"sequence_no"`
	DecisionID       string                 `json:"decision_id"`
	Kind             string                 `json:"kind"` // "HASH_CHAIN" | "DECISION_DRIFT"
	RecordedDecision domain.DecisionOutcome `json:"recorded_decision,omitempty"`
	ReplayedDecision domain.DecisionOutcome `json:"replayed_decision,omitempty"`
	RecordedCode     domain.ReasonCode      `json:"recorded_code,omitempty"`
	ReplayedCode     domain.ReasonCode      `json:"replayed_code,omitempty"`
	Detail           string                 `json:"detail"`
}

// ReplayReport summarizes cryptographic chain verification and deterministic policy replay.
type ReplayReport struct {
	TotalEvents       int              `json:"total_events"`
	VerifiedDecisions int              `json:"verified_decisions"`
	ChainValid        bool             `json:"chain_valid"`
	Passed            bool             `json:"passed"`
	Mismatches        []ReplayMismatch `json:"mismatches"`
}

// ReplayAuditLog verifies:
//  1. Sequence continuity and SHA-256 hash chain integrity across all audit events.
//  2. Deterministic re-evaluation of every recorded AUTHORIZATION decision via domain.EvaluatePolicyPure.
func ReplayAuditLog(events []domain.AuditEvent) ReplayReport {
	report := ReplayReport{
		TotalEvents: len(events),
		ChainValid:  true,
		Passed:      true,
		Mismatches:  []ReplayMismatch{},
	}

	expectedPrev := domain.GenesisAuditHash
	var expectedSeq int64 = 1

	for _, ev := range events {
		// 1. Sequence and hash chain integrity check.
		if ev.SequenceNo != expectedSeq {
			report.ChainValid = false
			report.Passed = false
			report.Mismatches = append(report.Mismatches, ReplayMismatch{
				SequenceNo: ev.SequenceNo,
				DecisionID: ev.DecisionID,
				Kind:       "HASH_CHAIN",
				Detail:     fmt.Sprintf("%s: expected sequence_no %d, got %d", domain.ReasonAuditTamperDetected, expectedSeq, ev.SequenceNo),
			})
		}
		if ev.PrevHash != expectedPrev {
			report.ChainValid = false
			report.Passed = false
			report.Mismatches = append(report.Mismatches, ReplayMismatch{
				SequenceNo: ev.SequenceNo,
				DecisionID: ev.DecisionID,
				Kind:       "HASH_CHAIN",
				Detail:     fmt.Sprintf("%s: prev_hash mismatch at seq %d", domain.ReasonAuditTamperDetected, ev.SequenceNo),
			})
		}
		recomputed := domain.ComputeAuditEntryHash(ev)
		if recomputed != ev.EntryHash {
			report.ChainValid = false
			report.Passed = false
			report.Mismatches = append(report.Mismatches, ReplayMismatch{
				SequenceNo: ev.SequenceNo,
				DecisionID: ev.DecisionID,
				Kind:       "HASH_CHAIN",
				Detail:     fmt.Sprintf("%s: entry_hash mismatch at seq %d (tampered record)", domain.ReasonAuditTamperDetected, ev.SequenceNo),
			})
		}
		expectedPrev = ev.EntryHash
		expectedSeq = ev.SequenceNo + 1

		// 2. Deterministic policy replay for every AUTHORIZATION event.
		if ev.EventType != "AUTHORIZATION" {
			continue
		}
		var env domain.ReplayEnvelope
		if err := json.Unmarshal([]byte(ev.ReplayEnvelopeJSON), &env); err != nil {
			report.Passed = false
			report.Mismatches = append(report.Mismatches, ReplayMismatch{
				SequenceNo: ev.SequenceNo,
				DecisionID: ev.DecisionID,
				Kind:       "DECISION_DRIFT",
				Detail:     fmt.Sprintf("corrupt replay envelope JSON: %v", err),
			})
			continue
		}
		var precomputedDigest string
		if env.MetadataRedacted {
			precomputedDigest = env.OriginalActionDigest
		}
		pureIn := domain.PurePolicyInput{
			Constraints: domain.PolicyConstraints{
				PolicyVersion:        env.PolicyVersion,
				ClockSkewSeconds:     env.ClockSkewSeconds,
				AllowedAudiences:     env.AllowedAudiences,
				SupportedActionTypes: env.SupportedActionTypes,
				SupportedCurrencies:  env.SupportedCurrencies,
			},
			Now:                     env.EvaluatedAtUTC,
			TokenValid:              env.TokenValid,
			TokenErrorCode:          env.TokenErrorCode,
			TokenErrorDetail:        env.TokenErrorDetail,
			Action:                  env.Action,
			PrecomputedActionDigest: precomputedDigest,
			GrantChain:              env.GrantChain,
			ActorActive:             env.ActorActive,
			Revoked:                 env.Revoked,
			RevocationReason:        env.RevocationReason,
			ApprovalProvided:        env.ApprovalProvided,
			ApprovalSigValid:        env.ApprovalSigValid,
			ApprovalAlreadyUsed:     env.ApprovalAlreadyUsed,
			ApprovalRecord:          env.ApprovalRecord,
		}
		replayed := domain.EvaluatePolicyPure(pureIn)
		if replayed.Decision != ev.Decision || replayed.ReasonCode != ev.ReasonCode {
			report.Passed = false
			report.Mismatches = append(report.Mismatches, ReplayMismatch{
				SequenceNo:       ev.SequenceNo,
				DecisionID:       ev.DecisionID,
				Kind:             "DECISION_DRIFT",
				RecordedDecision: ev.Decision,
				ReplayedDecision: replayed.Decision,
				RecordedCode:     ev.ReasonCode,
				ReplayedCode:     replayed.ReasonCode,
				Detail:           fmt.Sprintf("replayed (%s/%s) != recorded (%s/%s)", replayed.Decision, replayed.ReasonCode, ev.Decision, ev.ReasonCode),
			})
			continue
		}
		report.VerifiedDecisions++
	}

	return report
}
