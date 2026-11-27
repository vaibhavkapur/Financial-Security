package domain

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var principalIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// PolicyConstraints captures static policy allowlists for pure evaluation.
type PolicyConstraints struct {
	PolicyVersion        string
	MaxGrantTTLSeconds   int64
	MaxApprovalTTLSeconds int64
	MaxDelegationDepth   int
	ClockSkewSeconds     int64
	AllowedAudiences     []string
	SupportedActionTypes []string
	SupportedCurrencies  []string
}

// DomainError carries a structured ReasonCode and explanation.
type DomainError struct {
	Code   ReasonCode
	Detail string
}

func (e *DomainError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// NewDomainError creates a typed domain error.
func NewDomainError(code ReasonCode, format string, args ...any) *DomainError {
	return &DomainError{
		Code:   code,
		Detail: fmt.Sprintf(format, args...),
	}
}

func containsString(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// ValidatePrincipal checks principal identity contract invariants.
func ValidatePrincipal(p Principal) error {
	if !principalIDPattern.MatchString(p.PrincipalID) {
		return NewDomainError(ReasonInvalidInput, "invalid principal_id %q", p.PrincipalID)
	}
	switch p.PrincipalType {
	case PrincipalHumanDelegator, PrincipalServiceDelegator, PrincipalAgent:
	default:
		return NewDomainError(ReasonInvalidInput, "unsupported principal_type %q", p.PrincipalType)
	}
	if strings.TrimSpace(p.DisplayName) == "" || len(p.DisplayName) > 120 {
		return NewDomainError(ReasonInvalidInput, "display_name must be 1..120 chars")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return NewDomainError(ReasonInvalidInput, "tenant_id is required")
	}
	rawKey, err := base64.StdEncoding.DecodeString(p.PublicKeyB64)
	if err != nil || len(rawKey) != 32 {
		return NewDomainError(ReasonInvalidInput, "public_key_b64 must decode to a 32-byte Ed25519 public key")
	}
	if p.CreatedAtUTC.IsZero() {
		return NewDomainError(ReasonInvalidInput, "created_at_utc is required")
	}
	return nil
}

// ValidateScope validates a single scope entry against policy allowlists.
func ValidateScope(s Scope, pc PolicyConstraints) error {
	if !containsString(pc.SupportedActionTypes, s.ActionType) {
		return NewDomainError(ReasonUnsupportedAction, "unsupported action_type %q", s.ActionType)
	}
	pat := strings.TrimSpace(s.ResourcePattern)
	if pat == "" {
		return NewDomainError(ReasonInvalidInput, "resource_pattern is required")
	}
	if pat == "*" {
		return NewDomainError(ReasonInvalidInput, "bare wildcard resource_pattern '*' is forbidden by deny-by-default policy")
	}
	if strings.Count(pat, "*") > 1 {
		return NewDomainError(ReasonInvalidInput, "resource_pattern %q may contain at most one trailing '*'", pat)
	}
	if strings.Contains(pat, "*") && !strings.HasSuffix(pat, "*") {
		return NewDomainError(ReasonInvalidInput, "wildcard '*' in resource_pattern %q must be trailing only", pat)
	}
	return nil
}

// MatchResourcePattern matches resourceID against an exact pattern or single trailing '*' prefix.
func MatchResourcePattern(pattern, resourceID string) bool {
	if pattern == "" || resourceID == "" || pattern == "*" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return len(prefix) > 0 && strings.HasPrefix(resourceID, prefix)
	}
	return pattern == resourceID
}

// ScopeSubsumes returns true iff every resource matched by child is also matched by parent.
func ScopeSubsumes(parent, child Scope) bool {
	if parent.ActionType != child.ActionType {
		return false
	}
	if parent.ResourcePattern == "*" || child.ResourcePattern == "*" {
		return false
	}
	parentWild := strings.HasSuffix(parent.ResourcePattern, "*")
	childWild := strings.HasSuffix(child.ResourcePattern, "*")
	if !parentWild && !childWild {
		return parent.ResourcePattern == child.ResourcePattern
	}
	if !parentWild && childWild {
		// An exact parent pattern cannot subsume a wildcard child pattern.
		return false
	}
	parentPrefix := strings.TrimSuffix(parent.ResourcePattern, "*")
	if childWild {
		childPrefix := strings.TrimSuffix(child.ResourcePattern, "*")
		return strings.HasPrefix(childPrefix, parentPrefix)
	}
	return strings.HasPrefix(child.ResourcePattern, parentPrefix)
}

// ValidateSpendingLimit validates integer minor-unit spending bounds.
func ValidateSpendingLimit(sl SpendingLimit, pc PolicyConstraints) error {
	if !containsString(pc.SupportedCurrencies, sl.Currency) {
		return NewDomainError(ReasonUnsupportedCurrency, "unsupported currency %q", sl.Currency)
	}
	if sl.MaxPerActionMinor < 0 || sl.MaxCumulativeMinor < 0 || sl.RequireApprovalAboveMinor < 0 {
		return NewDomainError(ReasonInvalidInput, "spending limits must be non-negative minor units")
	}
	if sl.MaxPerActionMinor > sl.MaxCumulativeMinor {
		return NewDomainError(ReasonInvalidInput, "max_per_action_minor (%d) cannot exceed max_cumulative_minor (%d)", sl.MaxPerActionMinor, sl.MaxCumulativeMinor)
	}
	return nil
}

// ValidateGrantRequest validates a root or sub-delegated grant request against static policy constraints.
func ValidateGrantRequest(req GrantRequest, pc PolicyConstraints) error {
	if !principalIDPattern.MatchString(req.DelegatorID) {
		return NewDomainError(ReasonInvalidInput, "invalid delegator_id %q", req.DelegatorID)
	}
	if !principalIDPattern.MatchString(req.ActorID) {
		return NewDomainError(ReasonInvalidInput, "invalid actor_id %q", req.ActorID)
	}
	if req.DelegatorID == req.ActorID {
		return NewDomainError(ReasonInvalidInput, "self-delegation (%q -> %q) is prohibited", req.DelegatorID, req.ActorID)
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return NewDomainError(ReasonInvalidInput, "tenant_id is required")
	}
	if len(req.Audiences) == 0 {
		return NewDomainError(ReasonInvalidInput, "audiences must be non-empty")
	}
	for _, aud := range req.Audiences {
		if !containsString(pc.AllowedAudiences, aud) {
			return NewDomainError(ReasonAudienceMismatch, "audience %q is not in policy allowed_audiences", aud)
		}
	}
	if len(req.Scopes) == 0 {
		return NewDomainError(ReasonInvalidInput, "scopes must be non-empty")
	}
	for _, sc := range req.Scopes {
		if err := ValidateScope(sc, pc); err != nil {
			return err
		}
	}
	if err := ValidateSpendingLimit(req.SpendingLimit, pc); err != nil {
		return err
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > pc.MaxGrantTTLSeconds {
		return NewDomainError(ReasonInvalidInput, "ttl_seconds (%d) must be in 1..%d", req.TTLSeconds, pc.MaxGrantTTLSeconds)
	}
	return nil
}

// ValidateSubDelegation enforces strict monotonic attenuation so a child grant can NEVER escalate authority.
func ValidateSubDelegation(parent DelegationGrant, childReq GrantRequest, now time.Time, pc PolicyConstraints) error {
	if err := ValidateGrantRequest(childReq, pc); err != nil {
		return err
	}
	if !parent.CanDelegate {
		return NewDomainError(ReasonDelegationNotAllowed, "parent grant %q does not allow further delegation", parent.GrantID)
	}
	if parent.DelegationDepth+1 > pc.MaxDelegationDepth {
		return NewDomainError(ReasonDelegationDepthExceeded, "delegation depth %d exceeds policy max_delegation_depth %d", parent.DelegationDepth+1, pc.MaxDelegationDepth)
	}
	if !now.Before(parent.ExpiresAtUTC) {
		return NewDomainError(ReasonGrantExpired, "parent grant %q is expired", parent.GrantID)
	}
	if childReq.TenantID != parent.TenantID {
		return NewDomainError(ReasonDelegationEscalation, "cross-tenant sub-delegation denied (%q != %q)", childReq.TenantID, parent.TenantID)
	}
	if childReq.DelegatorID != parent.ActorID {
		return NewDomainError(ReasonDelegationEscalation, "sub-delegator %q must equal parent grant actor %q", childReq.DelegatorID, parent.ActorID)
	}
	// Audiences must be a subset of parent audiences.
	for _, aud := range childReq.Audiences {
		if !containsString(parent.Audiences, aud) {
			return NewDomainError(ReasonDelegationEscalation, "child audience %q is not permitted by parent grant %q", aud, parent.GrantID)
		}
	}
	// Every child scope must be subsumed by at least one parent scope.
	for _, cs := range childReq.Scopes {
		subsumed := false
		for _, ps := range parent.Scopes {
			if ScopeSubsumes(ps, cs) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			return NewDomainError(ReasonDelegationEscalation, "child scope (%s:%s) is wider than parent grant scopes", cs.ActionType, cs.ResourcePattern)
		}
	}
	// Counterparties cannot be dropped or widened if parent restricts them.
	if len(parent.AllowedCounterparties) > 0 {
		if len(childReq.AllowedCounterparties) == 0 {
			return NewDomainError(ReasonDelegationEscalation, "child grant cannot drop parent counterparty restrictions")
		}
		for _, cp := range childReq.AllowedCounterparties {
			if !containsString(parent.AllowedCounterparties, cp) {
				return NewDomainError(ReasonDelegationEscalation, "child counterparty %q is not permitted by parent grant", cp)
			}
		}
	}
	// Spending limits must be monotonically attenuated.
	if childReq.SpendingLimit.Currency != parent.SpendingLimit.Currency {
		return NewDomainError(ReasonDelegationEscalation, "child currency %q must match parent currency %q", childReq.SpendingLimit.Currency, parent.SpendingLimit.Currency)
	}
	if childReq.SpendingLimit.MaxPerActionMinor > parent.SpendingLimit.MaxPerActionMinor {
		return NewDomainError(ReasonDelegationEscalation, "child max_per_action_minor (%d) exceeds parent (%d)", childReq.SpendingLimit.MaxPerActionMinor, parent.SpendingLimit.MaxPerActionMinor)
	}
	parentRemaining := parent.SpendingLimit.MaxCumulativeMinor - parent.SpentCumulativeMinor
	if childReq.SpendingLimit.MaxCumulativeMinor > parent.SpendingLimit.MaxCumulativeMinor || childReq.SpendingLimit.MaxCumulativeMinor > parentRemaining {
		return NewDomainError(ReasonDelegationEscalation, "child max_cumulative_minor (%d) exceeds parent remaining allowance (%d)", childReq.SpendingLimit.MaxCumulativeMinor, parentRemaining)
	}
	if childReq.SpendingLimit.RequireApprovalAboveMinor > parent.SpendingLimit.RequireApprovalAboveMinor {
		return NewDomainError(ReasonDelegationEscalation, "child require_approval_above_minor (%d) cannot weaken parent threshold (%d)", childReq.SpendingLimit.RequireApprovalAboveMinor, parent.SpendingLimit.RequireApprovalAboveMinor)
	}
	// Validity window must fit inside parent window.
	nbf := now
	if childReq.NotBeforeUTC != nil {
		nbf = childReq.NotBeforeUTC.UTC().Truncate(time.Second)
	}
	if nbf.Before(parent.NotBeforeUTC) {
		return NewDomainError(ReasonDelegationEscalation, "child not_before_utc (%s) precedes parent (%s)", nbf.Format(time.RFC3339), parent.NotBeforeUTC.Format(time.RFC3339))
	}
	childExp := now.Add(time.Duration(childReq.TTLSeconds) * time.Second).UTC().Truncate(time.Second)
	if childExp.After(parent.ExpiresAtUTC) {
		return NewDomainError(ReasonDelegationEscalation, "child expires_at_utc (%s) exceeds parent expiry (%s)", childExp.Format(time.RFC3339), parent.ExpiresAtUTC.Format(time.RFC3339))
	}
	return nil
}

// ValidateActionPayload validates an ActionPayload against policy constraints.
func ValidateActionPayload(a ActionPayload, pc PolicyConstraints) error {
	if strings.TrimSpace(a.ActionID) == "" {
		return NewDomainError(ReasonInvalidInput, "action_id is required")
	}
	if !containsString(pc.SupportedActionTypes, a.ActionType) {
		return NewDomainError(ReasonUnsupportedAction, "unsupported action_type %q", a.ActionType)
	}
	if strings.TrimSpace(a.Audience) == "" {
		return NewDomainError(ReasonInvalidInput, "audience is required")
	}
	if !containsString(pc.AllowedAudiences, a.Audience) {
		return NewDomainError(ReasonAudienceMismatch, "audience %q is not in policy allowed_audiences", a.Audience)
	}
	if strings.TrimSpace(a.TenantID) == "" {
		return NewDomainError(ReasonInvalidInput, "tenant_id is required")
	}
	if strings.TrimSpace(a.ResourceID) == "" {
		return NewDomainError(ReasonInvalidInput, "resource_id is required")
	}
	if a.AmountMinor < 0 {
		return NewDomainError(ReasonInvalidInput, "amount_minor (%d) cannot be negative", a.AmountMinor)
	}
	if a.ActionType == "payment.initiate" {
		if a.AmountMinor <= 0 {
			return NewDomainError(ReasonInvalidInput, "payment.initiate requires positive amount_minor")
		}
		if strings.TrimSpace(a.CounterpartyID) == "" {
			return NewDomainError(ReasonInvalidInput, "payment.initiate requires counterparty_id")
		}
	}
	if a.AmountMinor > 0 {
		if !containsString(pc.SupportedCurrencies, a.Currency) {
			return NewDomainError(ReasonUnsupportedCurrency, "unsupported currency %q", a.Currency)
		}
	} else if a.Currency != "" && !containsString(pc.SupportedCurrencies, a.Currency) {
		return NewDomainError(ReasonUnsupportedCurrency, "unsupported currency %q", a.Currency)
	}
	return nil
}

// PurePolicyInput contains all state required for an I/O-free policy decision.
type PurePolicyInput struct {
	Constraints             PolicyConstraints
	Now                     time.Time
	TokenValid              bool
	TokenErrorCode          ReasonCode
	TokenErrorDetail        string
	Action                  ActionPayload
	PrecomputedActionDigest string // Optional: used only by Audit Replayer when metadata fields were redacted
	GrantChain              []DelegationGrant // index 0 = leaf grant, last = root grant
	ActorActive             bool
	Revoked                 bool
	RevocationReason        string
	ApprovalProvided        bool
	ApprovalSigValid        bool
	ApprovalAlreadyUsed     bool
	ApprovalRecord          *ApprovalRecord
}

// PurePolicyResult is the deterministic output of EvaluatePolicyPure.
type PurePolicyResult struct {
	Decision                 DecisionOutcome
	ReasonCode               ReasonCode
	ReasonDetail             string
	ActionDigest             string
	RemainingCumulativeMinor int64
}

// EvaluatePolicyPure performs the complete deny-by-default authorization algorithm with zero I/O.
// Both the live Enforcer and the Audit Replayer call this exact function.
func EvaluatePolicyPure(in PurePolicyInput) PurePolicyResult {
	digest := in.PrecomputedActionDigest
	if digest == "" {
		digest = ComputeActionDigest(in.Action)
	}
	deny := func(code ReasonCode, detail string, rem int64) PurePolicyResult {
		return PurePolicyResult{
			Decision:                 DecisionDeny,
			ReasonCode:               code,
			ReasonDetail:             detail,
			ActionDigest:             digest,
			RemainingCumulativeMinor: rem,
		}
	}

	// 1. Validate action payload first (fail closed on malformed/unsupported inputs).
	if err := ValidateActionPayload(in.Action, in.Constraints); err != nil {
		if de, ok := err.(*DomainError); ok {
			return deny(de.Code, de.Detail, 0)
		}
		return deny(ReasonInvalidInput, err.Error(), 0)
	}

	// 2. Cryptographic token check.
	if !in.TokenValid {
		code := in.TokenErrorCode
		if code == "" {
			code = ReasonTokenMalformed
		}
		return deny(code, in.TokenErrorDetail, 0)
	}

	// 3. Grant chain must exist.
	if len(in.GrantChain) == 0 {
		return deny(ReasonGrantNotFound, "grant not found in policy store", 0)
	}
	leaf := in.GrantChain[0]
	leafRemaining := leaf.SpendingLimit.MaxCumulativeMinor - leaf.SpentCumulativeMinor

	// 4. Actor active and revocation status across entire chain.
	if !in.ActorActive {
		return deny(ReasonActorInactive, fmt.Sprintf("actor %q is inactive or missing", leaf.ActorID), leafRemaining)
	}
	if in.Revoked {
		detail := in.RevocationReason
		if detail == "" {
			detail = "grant, ancestor grant, or principal has been revoked"
		}
		return deny(ReasonGrantRevoked, detail, leafRemaining)
	}

	// 5. Temporal validity across entire chain.
	skew := time.Duration(in.Constraints.ClockSkewSeconds) * time.Second
	now := in.Now.UTC().Truncate(time.Second)
	for _, g := range in.GrantChain {
		if now.Add(skew).Before(g.NotBeforeUTC) {
			return deny(ReasonGrantNotYetValid, fmt.Sprintf("grant %q not valid before %s", g.GrantID, g.NotBeforeUTC.Format(time.RFC3339)), leafRemaining)
		}
		if !now.Before(g.ExpiresAtUTC.Add(skew)) {
			return deny(ReasonGrantExpired, fmt.Sprintf("grant %q expired at %s", g.GrantID, g.ExpiresAtUTC.Format(time.RFC3339)), leafRemaining)
		}
	}

	// 6. Tenant, audience, scope, and counterparty checks across entire chain (defense-in-depth).
	for _, g := range in.GrantChain {
		if in.Action.TenantID != g.TenantID {
			return deny(ReasonTenantMismatch, fmt.Sprintf("action tenant %q does not match grant %q tenant %q", in.Action.TenantID, g.GrantID, g.TenantID), leafRemaining)
		}
		if !containsString(g.Audiences, in.Action.Audience) {
			return deny(ReasonAudienceMismatch, fmt.Sprintf("audience %q not permitted by grant %q", in.Action.Audience, g.GrantID), leafRemaining)
		}
		matchedScope := false
		for _, sc := range g.Scopes {
			if sc.ActionType == in.Action.ActionType && MatchResourcePattern(sc.ResourcePattern, in.Action.ResourceID) {
				matchedScope = true
				break
			}
		}
		if !matchedScope {
			return deny(ReasonScopeDenied, fmt.Sprintf("action %s on resource %q denied by grant %q scopes", in.Action.ActionType, in.Action.ResourceID, g.GrantID), leafRemaining)
		}
		if len(g.AllowedCounterparties) > 0 && in.Action.CounterpartyID != "" {
			if !containsString(g.AllowedCounterparties, in.Action.CounterpartyID) {
				return deny(ReasonCounterpartyDenied, fmt.Sprintf("counterparty %q not in allowlist of grant %q", in.Action.CounterpartyID, g.GrantID), leafRemaining)
			}
		}
	}

	// 7. Monetary limits across entire delegation chain.
	if in.Action.AmountMinor > 0 {
		for _, g := range in.GrantChain {
			if in.Action.Currency != g.SpendingLimit.Currency {
				return deny(ReasonCurrencyMismatch, fmt.Sprintf("action currency %q mismatches grant %q currency %q", in.Action.Currency, g.GrantID, g.SpendingLimit.Currency), leafRemaining)
			}
			if in.Action.AmountMinor > g.SpendingLimit.MaxPerActionMinor {
				return deny(ReasonPerActionLimitExceeded, fmt.Sprintf("amount %d exceeds grant %q max_per_action_minor %d", in.Action.AmountMinor, g.GrantID, g.SpendingLimit.MaxPerActionMinor), leafRemaining)
			}
			if g.SpentCumulativeMinor+in.Action.AmountMinor > g.SpendingLimit.MaxCumulativeMinor {
				return deny(ReasonCumulativeLimitExceeded, fmt.Sprintf("amount %d plus spent %d exceeds grant %q max_cumulative_minor %d", in.Action.AmountMinor, g.SpentCumulativeMinor, g.GrantID, g.SpendingLimit.MaxCumulativeMinor), leafRemaining)
			}
		}
	}

	// 8. Exact-action approval requirement (strictest threshold along chain).
	minApprovalThreshold := leaf.SpendingLimit.RequireApprovalAboveMinor
	for _, g := range in.GrantChain[1:] {
		if g.SpendingLimit.RequireApprovalAboveMinor < minApprovalThreshold {
			minApprovalThreshold = g.SpendingLimit.RequireApprovalAboveMinor
		}
	}
	approvalRequired := in.Action.AmountMinor > minApprovalThreshold
	if approvalRequired || in.ApprovalProvided {
		if !in.ApprovalProvided || in.ApprovalRecord == nil {
			return deny(ReasonApprovalRequired, fmt.Sprintf("amount %d exceeds approval threshold %d; exact-action approval required", in.Action.AmountMinor, minApprovalThreshold), leafRemaining)
		}
		ar := in.ApprovalRecord
		if ar.GrantID != leaf.GrantID || ar.ActorID != leaf.ActorID {
			return deny(ReasonApprovalBindingMismatch, fmt.Sprintf("approval %q bound to grant=%q actor=%q, got grant=%q actor=%q", ar.ApprovalID, ar.GrantID, ar.ActorID, leaf.GrantID, leaf.ActorID), leafRemaining)
		}
		if ar.ActionDigest != digest {
			return deny(ReasonApprovalPayloadMismatch, fmt.Sprintf("approval %q action_digest mismatch (possible altered amount or payload)", ar.ApprovalID), leafRemaining)
		}
		if !now.Before(ar.ExpiresAtUTC.Add(skew)) {
			return deny(ReasonApprovalExpired, fmt.Sprintf("approval %q expired at %s", ar.ApprovalID, ar.ExpiresAtUTC.Format(time.RFC3339)), leafRemaining)
		}
		if !in.ApprovalSigValid {
			return deny(ReasonApprovalInvalidSig, fmt.Sprintf("approval %q cryptographic signature or approver authority invalid", ar.ApprovalID), leafRemaining)
		}
		if in.ApprovalAlreadyUsed {
			return deny(ReasonApprovalAlreadyUsed, fmt.Sprintf("approval %q has already been consumed", ar.ApprovalID), leafRemaining)
		}
	}

	return PurePolicyResult{
		Decision:                 DecisionAllow,
		ReasonCode:               ReasonAllowAuthorized,
		ReasonDetail:             "authorized under bounded delegated grant",
		ActionDigest:             digest,
		RemainingCumulativeMinor: leafRemaining - in.Action.AmountMinor,
	}
}
