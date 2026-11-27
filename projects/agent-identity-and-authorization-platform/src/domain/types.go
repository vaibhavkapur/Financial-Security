package domain

import (
	"time"
)

// PrincipalType classifies actors and delegators.
type PrincipalType string

const (
	PrincipalHumanDelegator   PrincipalType = "human_delegator"
	PrincipalServiceDelegator PrincipalType = "service_delegator"
	PrincipalAgent            PrincipalType = "agent"
)

// DecisionOutcome is the authorization verdict.
type DecisionOutcome string

const (
	DecisionAllow DecisionOutcome = "ALLOW"
	DecisionDeny  DecisionOutcome = "DENY"
	DecisionEvent DecisionOutcome = "EVENT"
)

// ReasonCode is a stable, machine-readable policy/validation result code.
type ReasonCode string

const (
	ReasonAllowAuthorized          ReasonCode = "ALLOW_AUTHORIZED"
	ReasonInvalidConfig            ReasonCode = "ERR_INVALID_CONFIG"
	ReasonInvalidInput             ReasonCode = "ERR_INVALID_INPUT"
	ReasonUnsupportedAction        ReasonCode = "ERR_UNSUPPORTED_ACTION"
	ReasonUnsupportedCurrency      ReasonCode = "ERR_UNSUPPORTED_CURRENCY"
	ReasonTokenMalformed           ReasonCode = "ERR_TOKEN_MALFORMED"
	ReasonTokenInvalidAlg          ReasonCode = "ERR_TOKEN_INVALID_ALG"
	ReasonTokenInvalidSig          ReasonCode = "ERR_TOKEN_INVALID_SIG"
	ReasonGrantExpired             ReasonCode = "ERR_GRANT_EXPIRED"
	ReasonGrantNotYetValid         ReasonCode = "ERR_GRANT_NOT_YET_VALID"
	ReasonGrantNotFound            ReasonCode = "ERR_GRANT_NOT_FOUND"
	ReasonGrantTokenMismatch       ReasonCode = "ERR_GRANT_TOKEN_MISMATCH"
	ReasonGrantRevoked             ReasonCode = "ERR_GRANT_REVOKED"
	ReasonActorInactive            ReasonCode = "ERR_ACTOR_INACTIVE"
	ReasonTenantMismatch           ReasonCode = "ERR_TENANT_MISMATCH"
	ReasonAudienceMismatch         ReasonCode = "ERR_AUDIENCE_MISMATCH"
	ReasonScopeDenied              ReasonCode = "ERR_SCOPE_DENIED"
	ReasonCounterpartyDenied       ReasonCode = "ERR_COUNTERPARTY_DENIED"
	ReasonCurrencyMismatch         ReasonCode = "ERR_CURRENCY_MISMATCH"
	ReasonPerActionLimitExceeded   ReasonCode = "ERR_PER_ACTION_LIMIT_EXCEEDED"
	ReasonCumulativeLimitExceeded  ReasonCode = "ERR_CUMULATIVE_LIMIT_EXCEEDED"
	ReasonApprovalRequired         ReasonCode = "ERR_APPROVAL_REQUIRED"
	ReasonApprovalInvalidSig       ReasonCode = "ERR_APPROVAL_INVALID_SIG"
	ReasonApprovalExpired          ReasonCode = "ERR_APPROVAL_EXPIRED"
	ReasonApprovalBindingMismatch  ReasonCode = "ERR_APPROVAL_BINDING_MISMATCH"
	ReasonApprovalPayloadMismatch  ReasonCode = "ERR_APPROVAL_PAYLOAD_MISMATCH"
	ReasonApprovalAlreadyUsed      ReasonCode = "ERR_APPROVAL_ALREADY_USED"
	ReasonDelegationNotAllowed     ReasonCode = "ERR_DELEGATION_NOT_ALLOWED"
	ReasonDelegationDepthExceeded  ReasonCode = "ERR_DELEGATION_DEPTH_EXCEEDED"
	ReasonDelegationEscalation     ReasonCode = "ERR_DELEGATION_ESCALATION"
	ReasonAuditTamperDetected      ReasonCode = "ERR_AUDIT_TAMPER_DETECTED"
	ReasonRevocationRecorded       ReasonCode = "EVENT_REVOCATION_RECORDED"
	ReasonGrantIssued              ReasonCode = "EVENT_GRANT_ISSUED"
)

// Clock abstracts time for deterministic evaluation, testing, and audit replay.
type Clock interface {
	Now() time.Time
}

// RealClock returns wall-clock UTC time truncated to seconds.
type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// FixedClock is a deterministic controllable clock for tests and fixtures.
type FixedClock struct {
	Current time.Time
}

func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{Current: t.UTC().Truncate(time.Second)}
}

func (c *FixedClock) Now() time.Time {
	return c.Current.UTC().Truncate(time.Second)
}

func (c *FixedClock) Advance(d time.Duration) {
	c.Current = c.Current.Add(d).UTC().Truncate(time.Second)
}

// Principal represents a human/service delegator or a simulated financial agent.
type Principal struct {
	PrincipalID   string        `json:"principal_id"`
	PrincipalType PrincipalType `json:"principal_type"`
	DisplayName   string        `json:"display_name"`
	TenantID      string        `json:"tenant_id"`
	PublicKeyB64  string        `json:"public_key_b64"`
	Active        bool          `json:"active"`
	CreatedAtUTC  time.Time     `json:"created_at_utc"`
}

// Scope binds an explicit action type to a resource pattern.
type Scope struct {
	ActionType      string `json:"action_type"`
	ResourcePattern string `json:"resource_pattern"`
}

// SpendingLimit expresses monetary caps in integer minor units (e.g., USD cents).
type SpendingLimit struct {
	Currency                  string `json:"currency"`
	MaxPerActionMinor         int64  `json:"max_per_action_minor"`
	MaxCumulativeMinor        int64  `json:"max_cumulative_minor"`
	RequireApprovalAboveMinor int64  `json:"require_approval_above_minor"`
}

// GrantRequest defines inputs to issue a root or sub-delegated grant.
type GrantRequest struct {
	GrantID              string        `json:"grant_id,omitempty"`
	ParentGrantID        string        `json:"parent_grant_id,omitempty"`
	CanDelegate          bool          `json:"can_delegate"`
	DelegatorID          string        `json:"delegator_id"`
	ActorID              string        `json:"actor_id"`
	TenantID             string        `json:"tenant_id"`
	Audiences            []string      `json:"audiences"`
	Scopes               []Scope       `json:"scopes"`
	AllowedCounterparties []string     `json:"allowed_counterparties,omitempty"`
	SpendingLimit        SpendingLimit `json:"spending_limit"`
	NotBeforeUTC         *time.Time    `json:"not_before_utc,omitempty"`
	TTLSeconds           int64         `json:"ttl_seconds"`
}

// DelegationGrant is the persisted, authoritative record of an issued short-lived grant.
type DelegationGrant struct {
	GrantID               string        `json:"grant_id"`
	ParentGrantID         string        `json:"parent_grant_id,omitempty"`
	RootGrantID           string        `json:"root_grant_id"`
	DelegationDepth       int           `json:"delegation_depth"`
	CanDelegate           bool          `json:"can_delegate"`
	IssuerID              string        `json:"issuer_id"`
	DelegatorID           string        `json:"delegator_id"`
	ActorID               string        `json:"actor_id"`
	TenantID              string        `json:"tenant_id"`
	Audiences             []string      `json:"audiences"`
	Scopes                []Scope       `json:"scopes"`
	AllowedCounterparties []string      `json:"allowed_counterparties,omitempty"`
	SpendingLimit         SpendingLimit `json:"spending_limit"`
	SpentCumulativeMinor  int64         `json:"spent_cumulative_minor"`
	IssuedAtUTC           time.Time     `json:"issued_at_utc"`
	NotBeforeUTC          time.Time     `json:"not_before_utc"`
	ExpiresAtUTC          time.Time     `json:"expires_at_utc"`
	TokenHash             string        `json:"token_hash"`
	CreatedSeq            int64         `json:"created_seq"`
}

// IssuedGrant pairs the persisted grant metadata with its signed EdDSA JWT.
type IssuedGrant struct {
	Grant DelegationGrant `json:"grant"`
	Token string          `json:"token"`
}

// ActionPayload represents a simulated financial action submitted for authorization.
type ActionPayload struct {
	ActionID       string            `json:"action_id"`
	ActionType     string            `json:"action_type"`
	Audience       string            `json:"audience"`
	TenantID       string            `json:"tenant_id"`
	ResourceID     string            `json:"resource_id"`
	CounterpartyID string            `json:"counterparty_id,omitempty"`
	AmountMinor    int64             `json:"amount_minor"`
	Currency       string            `json:"currency,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ApprovalRecord is an exact-action, single-use, delegator-signed approval.
type ApprovalRecord struct {
	ApprovalID           string     `json:"approval_id"`
	GrantID              string     `json:"grant_id"`
	ActorID              string     `json:"actor_id"`
	ApproverID           string     `json:"approver_id"`
	ActionDigest         string     `json:"action_digest"`
	Nonce                string     `json:"nonce"`
	IssuedAtUTC          time.Time  `json:"issued_at_utc"`
	ExpiresAtUTC         time.Time  `json:"expires_at_utc"`
	SignatureB64         string     `json:"signature_b64"`
	ConsumedAtUTC        *time.Time `json:"consumed_at_utc,omitempty"`
	ConsumedByDecisionID string     `json:"consumed_by_decision_id,omitempty"`
}

// RevocationTarget identifies what entity a revocation applies to.
type RevocationTarget string

const (
	RevokeGrant     RevocationTarget = "grant"
	RevokeActor     RevocationTarget = "actor"
	RevokeDelegator RevocationTarget = "delegator"
)

// RevocationRecord records an immediate revocation.
type RevocationRecord struct {
	RevocationID string           `json:"revocation_id"`
	TargetType   RevocationTarget `json:"target_type"`
	TargetID     string           `json:"target_id"`
	RevokedBy    string           `json:"revoked_by"`
	Reason       string           `json:"reason"`
	RevokedAtUTC time.Time        `json:"revoked_at_utc"`
	RevokedSeq   int64            `json:"revoked_seq"`
}

// AuthorizationRequest is submitted by an agent to the Policy Enforcement Point.
type AuthorizationRequest struct {
	DecisionID string          `json:"decision_id,omitempty"`
	GrantToken string          `json:"grant_token"`
	Action     ActionPayload   `json:"action"`
	Approval   *ApprovalRecord `json:"approval,omitempty"`
}

// AuthorizationDecision is the authoritative output contract for enforcement.
type AuthorizationDecision struct {
	DecisionID               string          `json:"decision_id"`
	SequenceNo               int64           `json:"sequence_no"`
	Decision                 DecisionOutcome `json:"decision"`
	ReasonCode               ReasonCode      `json:"reason_code"`
	ReasonDetail             string          `json:"reason_detail"`
	PolicyVersion            string          `json:"policy_version"`
	GrantID                  string          `json:"grant_id,omitempty"`
	ActorID                  string          `json:"actor_id,omitempty"`
	ActionDigest             string          `json:"action_digest"`
	ApprovalID               string          `json:"approval_id,omitempty"`
	RemainingCumulativeMinor int64           `json:"remaining_cumulative_minor"`
	EvaluatedAtUTC           time.Time       `json:"evaluated_at_utc"`
	AuditEntryHash           string          `json:"audit_entry_hash"`
}

// ReplayEnvelope captures the exact pre-decision snapshot needed for deterministic replay.
type ReplayEnvelope struct {
	PolicyVersion          string             `json:"policy_version"`
	EvaluatedAtUTC         time.Time          `json:"evaluated_at_utc"`
	ClockSkewSeconds       int64              `json:"clock_skew_seconds"`
	SupportedActionTypes   []string           `json:"supported_action_types"`
	SupportedCurrencies    []string           `json:"supported_currencies"`
	AllowedAudiences       []string           `json:"allowed_audiences"`
	TokenValid             bool               `json:"token_valid"`
	TokenErrorCode         ReasonCode         `json:"token_error_code,omitempty"`
	TokenErrorDetail       string             `json:"token_error_detail,omitempty"`
	Action                 ActionPayload      `json:"action"`
	MetadataRedacted       bool               `json:"metadata_redacted,omitempty"`
	OriginalActionDigest   string             `json:"original_action_digest,omitempty"`
	GrantChain             []DelegationGrant  `json:"grant_chain,omitempty"`
	ActorActive            bool               `json:"actor_active"`
	Revoked                bool               `json:"revoked"`
	RevocationReason       string             `json:"revocation_reason,omitempty"`
	ApprovalProvided       bool               `json:"approval_provided"`
	ApprovalSigValid       bool               `json:"approval_sig_valid"`
	ApprovalAlreadyUsed    bool               `json:"approval_already_used"`
	ApprovalRecord         *ApprovalRecord    `json:"approval_record,omitempty"`
}

// AuditEvent is one immutable, hash-chained record in the audit log.
type AuditEvent struct {
	SequenceNo          int64           `json:"sequence_no"`
	DecisionID          string          `json:"decision_id"`
	EventType           string          `json:"event_type"`
	TimestampUTC        time.Time       `json:"timestamp_utc"`
	PolicyVersion       string          `json:"policy_version"`
	GrantID             string          `json:"grant_id"`
	ParentGrantID       string          `json:"parent_grant_id,omitempty"`
	ActorID             string          `json:"actor_id"`
	DelegatorID         string          `json:"delegator_id"`
	Audience            string          `json:"audience"`
	ActionType          string          `json:"action_type"`
	ResourceID          string          `json:"resource_id"`
	AmountMinor         int64           `json:"amount_minor"`
	Currency            string          `json:"currency"`
	ActionDigest        string          `json:"action_digest"`
	ApprovalID          string          `json:"approval_id,omitempty"`
	Decision            DecisionOutcome `json:"decision"`
	ReasonCode          ReasonCode      `json:"reason_code"`
	ReasonDetail        string          `json:"reason_detail"`
	RedactedPayloadJSON string          `json:"redacted_payload_json"`
	ReplayEnvelopeJSON  string          `json:"replay_envelope_json"`
	PrevHash            string          `json:"prev_hash"`
	EntryHash           string          `json:"entry_hash"`
}
