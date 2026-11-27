package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	actionDigestDomainPrefix   = "aiap.action.v1:"
	approvalSignDomainPrefix   = "aiap.approval.v1:"
	auditHashDomainPrefix      = "aiap.audit.v1:"
	GenesisAuditHash           = "0000000000000000000000000000000000000000000000000000000000000000"
)

type canonicalKV struct {
	K string `json:"k"`
	V string `json:"v"`
}

type canonicalAction struct {
	ActionID       string        `json:"action_id"`
	ActionType     string        `json:"action_type"`
	AmountMinor    int64         `json:"amount_minor"`
	Audience       string        `json:"audience"`
	CounterpartyID string        `json:"counterparty_id"`
	Currency       string        `json:"currency"`
	Metadata       []canonicalKV `json:"metadata"`
	ResourceID     string        `json:"resource_id"`
	TenantID       string        `json:"tenant_id"`
}

// CanonicalActionBytes produces the deterministic domain-separated bytes for an ActionPayload.
func CanonicalActionBytes(a ActionPayload) []byte {
	keys := make([]string, 0, len(a.Metadata))
	for k := range a.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	meta := make([]canonicalKV, 0, len(keys))
	for _, k := range keys {
		meta = append(meta, canonicalKV{K: k, V: a.Metadata[k]})
	}
	ca := canonicalAction{
		ActionID:       a.ActionID,
		ActionType:     a.ActionType,
		AmountMinor:    a.AmountMinor,
		Audience:       a.Audience,
		CounterpartyID: a.CounterpartyID,
		Currency:       strings.ToUpper(a.Currency),
		Metadata:       meta,
		ResourceID:     a.ResourceID,
		TenantID:       a.TenantID,
	}
	encoded, _ := json.Marshal(ca)
	return append([]byte(actionDigestDomainPrefix), encoded...)
}

// ComputeActionDigest returns the hex-encoded SHA-256 exact-action digest.
func ComputeActionDigest(a ActionPayload) string {
	sum := sha256.Sum256(CanonicalActionBytes(a))
	return hex.EncodeToString(sum[:])
}

type canonicalApproval struct {
	ActionDigest string `json:"action_digest"`
	ActorID      string `json:"actor_id"`
	ApprovalID   string `json:"approval_id"`
	ApproverID   string `json:"approver_id"`
	ExpiresAtUTC string `json:"expires_at_utc"`
	GrantID      string `json:"grant_id"`
	IssuedAtUTC  string `json:"issued_at_utc"`
	Nonce        string `json:"nonce"`
}

// CanonicalApprovalSigningBytes builds the exact deterministic message signed by an approver.
func CanonicalApprovalSigningBytes(r ApprovalRecord) []byte {
	ca := canonicalApproval{
		ActionDigest: r.ActionDigest,
		ActorID:      r.ActorID,
		ApprovalID:   r.ApprovalID,
		ApproverID:   r.ApproverID,
		ExpiresAtUTC: r.ExpiresAtUTC.UTC().Truncate(time.Second).Format(time.RFC3339),
		GrantID:      r.GrantID,
		IssuedAtUTC:  r.IssuedAtUTC.UTC().Truncate(time.Second).Format(time.RFC3339),
		Nonce:        r.Nonce,
	}
	encoded, _ := json.Marshal(ca)
	return append([]byte(approvalSignDomainPrefix), encoded...)
}

// ComputeTokenHash computes the SHA-256 hex digest of a signed JWT string so raw tokens are never persisted.
func ComputeTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ComputeAuditEntryHash computes the deterministic SHA-256 chain hash for an AuditEvent.
func ComputeAuditEntryHash(e AuditEvent) string {
	payload := fmt.Sprintf(
		"%s%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s",
		auditHashDomainPrefix,
		e.SequenceNo,
		e.DecisionID,
		e.EventType,
		e.TimestampUTC.UTC().Truncate(time.Second).Format(time.RFC3339),
		e.PolicyVersion,
		e.GrantID,
		e.ParentGrantID,
		e.ActorID,
		e.DelegatorID,
		e.Audience,
		e.ActionType,
		e.ResourceID,
		e.AmountMinor,
		e.Currency,
		e.ActionDigest,
		e.ApprovalID,
		string(e.Decision),
		string(e.ReasonCode),
		e.ReasonDetail,
		e.RedactedPayloadJSON,
		e.PrevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// RedactActionPayload returns a redacted JSON string for safe telemetry and audit storage.
func RedactActionPayload(a ActionPayload, redactFields []string, replacement string) string {
	sensitive := make(map[string]struct{}, len(redactFields))
	for _, f := range redactFields {
		sensitive[strings.ToLower(strings.TrimSpace(f))] = struct{}{}
	}
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	redactedMeta := make(map[string]string, len(a.Metadata))
	for k, v := range a.Metadata {
		lk := strings.ToLower(k)
		redact := false
		if _, ok := sensitive[lk]; ok {
			redact = true
		} else {
			for sf := range sensitive {
				if sf != "" && strings.Contains(lk, sf) {
					redact = true
					break
				}
			}
		}
		if redact {
			redactedMeta[k] = replacement
		} else {
			redactedMeta[k] = v
		}
	}
	clone := a
	clone.Metadata = redactedMeta
	b, _ := json.Marshal(clone)
	return string(b)
}
