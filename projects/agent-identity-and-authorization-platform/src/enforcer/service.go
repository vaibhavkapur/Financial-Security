package enforcer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

// MetricsSnapshot captures structured diagnostic counters for operational observability.
type MetricsSnapshot struct {
	GrantsIssued        int64                        `json:"grants_issued"`
	SubGrantsIssued     int64                        `json:"sub_grants_issued"`
	RevocationsRecorded int64                        `json:"revocations_recorded"`
	ApprovalsConsumed   int64                        `json:"approvals_consumed"`
	TotalAuthorizations int64                        `json:"total_authorizations"`
	AllowCount          int64                        `json:"allow_count"`
	DenyCount           int64                        `json:"deny_count"`
	DeniesByReason      map[domain.ReasonCode]int64  `json:"denies_by_reason"`
}

// PlatformService coordinates identity registration, grant issuance, revocation,
// exact-action approval management, and deny-by-default enforcement.
type PlatformService struct {
	cfg      config.Config
	store    store.Store
	signer   crypto.GrantSigner
	verifier crypto.GrantVerifier
	clock    domain.Clock
	logger   *slog.Logger

	mu      sync.Mutex
	metrics MetricsSnapshot
}

// NewPlatformService constructs a validated PlatformService.
func NewPlatformService(
	cfg config.Config,
	st store.Store,
	authorityKey crypto.KeyPair,
	clock domain.Clock,
	logWriter io.Writer,
) (*PlatformService, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("%w: store must not be nil", config.ErrInvalidConfig)
	}
	if len(authorityKey.PrivateKey) != ed25519.PrivateKeySize || len(authorityKey.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: authority Ed25519 key pair is invalid", config.ErrInvalidConfig)
	}
	if clock == nil {
		clock = domain.RealClock{}
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))
	pubMap := map[string]ed25519.PublicKey{}
	if authorityKey.KeyID != "" {
		pubMap[authorityKey.KeyID] = authorityKey.PublicKey
	}
	return &PlatformService{
		cfg:   cfg,
		store: st,
		signer: crypto.GrantSigner{
			Key: authorityKey,
		},
		verifier: crypto.GrantVerifier{
			IssuerID:         cfg.IssuerID,
			PublicKeysByKID:  pubMap,
			DefaultPublicKey: authorityKey.PublicKey,
			ClockSkewSeconds: cfg.ClockSkewSeconds,
		},
		clock:  clock,
		logger: logger,
		metrics: MetricsSnapshot{
			DeniesByReason: make(map[domain.ReasonCode]int64),
		},
	}, nil
}

func (s *PlatformService) constraints() domain.PolicyConstraints {
	return domain.PolicyConstraints{
		PolicyVersion:         s.cfg.PolicyVersion,
		MaxGrantTTLSeconds:    s.cfg.MaxGrantTTLSeconds,
		MaxApprovalTTLSeconds: s.cfg.MaxApprovalTTLSeconds,
		MaxDelegationDepth:    s.cfg.MaxDelegationDepth,
		ClockSkewSeconds:      s.cfg.ClockSkewSeconds,
		AllowedAudiences:      s.cfg.AllowedAudiences,
		SupportedActionTypes:  s.cfg.SupportedActionTypes,
		SupportedCurrencies:   s.cfg.SupportedCurrencies,
	}
}

// Metrics returns a thread-safe copy of diagnostic counters.
func (s *PlatformService) Metrics() MetricsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := s.metrics
	cp.DeniesByReason = make(map[domain.ReasonCode]int64, len(s.metrics.DeniesByReason))
	for k, v := range s.metrics.DeniesByReason {
		cp.DeniesByReason[k] = v
	}
	return cp
}

// RegisterPrincipal validates and stores a delegator or agent identity.
func (s *PlatformService) RegisterPrincipal(ctx context.Context, p domain.Principal) error {
	if p.CreatedAtUTC.IsZero() {
		p.CreatedAtUTC = s.clock.Now()
	}
	if err := domain.ValidatePrincipal(p); err != nil {
		return err
	}
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.UpsertPrincipal(ctx, p)
	})
}

// IssueRootGrant validates delegator/actor principals and issues a short-lived EdDSA signed root grant.
func (s *PlatformService) IssueRootGrant(ctx context.Context, req domain.GrantRequest) (domain.IssuedGrant, error) {
	if req.ParentGrantID != "" {
		return domain.IssuedGrant{}, domain.NewDomainError(domain.ReasonInvalidInput, "IssueRootGrant called with non-empty parent_grant_id")
	}
	if err := domain.ValidateGrantRequest(req, s.constraints()); err != nil {
		return domain.IssuedGrant{}, err
	}
	now := s.clock.Now()
	nbf := now
	if req.NotBeforeUTC != nil {
		nbf = req.NotBeforeUTC.UTC().Truncate(time.Second)
	}
	exp := now.Add(time.Duration(req.TTLSeconds) * time.Second).UTC().Truncate(time.Second)
	grantID := req.GrantID
	if grantID == "" {
		grantID = "grt_" + uuid.NewString()
	}

	var issued domain.IssuedGrant
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		delegator, err := tx.GetPrincipal(ctx, req.DelegatorID)
		if err != nil {
			return err
		}
		if delegator == nil || !delegator.Active {
			return domain.NewDomainError(domain.ReasonActorInactive, "delegator %q not found or inactive", req.DelegatorID)
		}
		if delegator.PrincipalType == domain.PrincipalAgent {
			return domain.NewDomainError(domain.ReasonDelegationNotAllowed, "root grant delegator %q cannot be an agent (use sub-delegation)", req.DelegatorID)
		}
		if delegator.TenantID != req.TenantID {
			return domain.NewDomainError(domain.ReasonTenantMismatch, "delegator tenant %q mismatches grant tenant %q", delegator.TenantID, req.TenantID)
		}
		actor, err := tx.GetPrincipal(ctx, req.ActorID)
		if err != nil {
			return err
		}
		if actor == nil || !actor.Active {
			return domain.NewDomainError(domain.ReasonActorInactive, "actor %q not found or inactive", req.ActorID)
		}
		if actor.TenantID != req.TenantID {
			return domain.NewDomainError(domain.ReasonTenantMismatch, "actor tenant %q mismatches grant tenant %q", actor.TenantID, req.TenantID)
		}
		if revoked, reason, err := tx.IsRevoked(ctx, domain.RevokeDelegator, req.DelegatorID); err != nil {
			return err
		} else if revoked {
			return domain.NewDomainError(domain.ReasonGrantRevoked, "delegator %q is revoked: %s", req.DelegatorID, reason)
		}
		if revoked, reason, err := tx.IsRevoked(ctx, domain.RevokeActor, req.ActorID); err != nil {
			return err
		} else if revoked {
			return domain.NewDomainError(domain.ReasonGrantRevoked, "actor %q is revoked: %s", req.ActorID, reason)
		}

		seq, err := tx.NextSequence(ctx)
		if err != nil {
			return err
		}
		g := domain.DelegationGrant{
			GrantID:               grantID,
			ParentGrantID:         "",
			RootGrantID:           grantID,
			DelegationDepth:       0,
			CanDelegate:           req.CanDelegate,
			IssuerID:              s.cfg.IssuerID,
			DelegatorID:           req.DelegatorID,
			ActorID:               req.ActorID,
			TenantID:              req.TenantID,
			Audiences:             append([]string(nil), req.Audiences...),
			Scopes:                append([]domain.Scope(nil), req.Scopes...),
			AllowedCounterparties: append([]string(nil), req.AllowedCounterparties...),
			SpendingLimit:         req.SpendingLimit,
			SpentCumulativeMinor:  0,
			IssuedAtUTC:           now,
			NotBeforeUTC:          nbf,
			ExpiresAtUTC:          exp,
			CreatedSeq:            seq,
		}
		tok, err := s.signer.SignGrant(g)
		if err != nil {
			return err
		}
		g.TokenHash = domain.ComputeTokenHash(tok)
		if err := tx.InsertGrant(ctx, g); err != nil {
			return err
		}
		ev := &domain.AuditEvent{
			DecisionID:          "evt_grant_" + grantID,
			EventType:           "GRANT_ISSUED",
			TimestampUTC:        now,
			PolicyVersion:       s.cfg.PolicyVersion,
			GrantID:             g.GrantID,
			ActorID:             g.ActorID,
			DelegatorID:         g.DelegatorID,
			Audience:            fmt.Sprintf("%v", g.Audiences),
			ActionType:          "grant.issue_root",
			ResourceID:          g.GrantID,
			AmountMinor:         g.SpendingLimit.MaxCumulativeMinor,
			Currency:            g.SpendingLimit.Currency,
			ActionDigest:        g.TokenHash,
			Decision:            domain.DecisionEvent,
			ReasonCode:          domain.ReasonGrantIssued,
			ReasonDetail:        "root delegation grant issued",
			RedactedPayloadJSON: "{}",
			ReplayEnvelopeJSON:  "{}",
		}
		if err := tx.AppendAuditEvent(ctx, ev); err != nil {
			return err
		}
		issued = domain.IssuedGrant{Grant: g, Token: tok}
		return nil
	})
	if err != nil {
		return domain.IssuedGrant{}, err
	}
	s.mu.Lock()
	s.metrics.GrantsIssued++
	s.mu.Unlock()
	s.logger.Info("root_grant_issued", "grant_id", issued.Grant.GrantID, "delegator_id", issued.Grant.DelegatorID, "actor_id", issued.Grant.ActorID)
	return issued, nil
}

// IssueSubDelegatedGrant issues an attenuated child grant strictly bounded by its parent grant.
func (s *PlatformService) IssueSubDelegatedGrant(ctx context.Context, req domain.GrantRequest) (domain.IssuedGrant, error) {
	if req.ParentGrantID == "" {
		return domain.IssuedGrant{}, domain.NewDomainError(domain.ReasonInvalidInput, "parent_grant_id is required for sub-delegation")
	}
	now := s.clock.Now()
	grantID := req.GrantID
	if grantID == "" {
		grantID = "grt_" + uuid.NewString()
	}

	var issued domain.IssuedGrant
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		chain, err := tx.GetGrantChain(ctx, req.ParentGrantID)
		if err != nil {
			return err
		}
		if len(chain) == 0 {
			return domain.NewDomainError(domain.ReasonGrantNotFound, "parent grant %q not found", req.ParentGrantID)
		}
		// Ensure no ancestor grant or principal in the chain is revoked.
		for _, anc := range chain {
			if revoked, reason, err := tx.IsRevoked(ctx, domain.RevokeGrant, anc.GrantID); err != nil {
				return err
			} else if revoked {
				return domain.NewDomainError(domain.ReasonGrantRevoked, "ancestor grant %q is revoked: %s", anc.GrantID, reason)
			}
		}
		parent := chain[0]
		if err := domain.ValidateSubDelegation(parent, req, now, s.constraints()); err != nil {
			return err
		}
		actor, err := tx.GetPrincipal(ctx, req.ActorID)
		if err != nil {
			return err
		}
		if actor == nil || !actor.Active {
			return domain.NewDomainError(domain.ReasonActorInactive, "child actor %q not found or inactive", req.ActorID)
		}
		if actor.TenantID != parent.TenantID {
			return domain.NewDomainError(domain.ReasonDelegationEscalation, "child actor tenant %q mismatches parent tenant %q", actor.TenantID, parent.TenantID)
		}
		if revoked, reason, err := tx.IsRevoked(ctx, domain.RevokeActor, req.ActorID); err != nil {
			return err
		} else if revoked {
			return domain.NewDomainError(domain.ReasonGrantRevoked, "child actor %q is revoked: %s", req.ActorID, reason)
		}

		nbf := now
		if req.NotBeforeUTC != nil {
			nbf = req.NotBeforeUTC.UTC().Truncate(time.Second)
		}
		exp := now.Add(time.Duration(req.TTLSeconds) * time.Second).UTC().Truncate(time.Second)
		seq, err := tx.NextSequence(ctx)
		if err != nil {
			return err
		}
		child := domain.DelegationGrant{
			GrantID:               grantID,
			ParentGrantID:         parent.GrantID,
			RootGrantID:           parent.RootGrantID,
			DelegationDepth:       parent.DelegationDepth + 1,
			CanDelegate:           req.CanDelegate,
			IssuerID:              s.cfg.IssuerID,
			DelegatorID:           req.DelegatorID,
			ActorID:               req.ActorID,
			TenantID:              parent.TenantID,
			Audiences:             append([]string(nil), req.Audiences...),
			Scopes:                append([]domain.Scope(nil), req.Scopes...),
			AllowedCounterparties: append([]string(nil), req.AllowedCounterparties...),
			SpendingLimit:         req.SpendingLimit,
			SpentCumulativeMinor:  0,
			IssuedAtUTC:           now,
			NotBeforeUTC:          nbf,
			ExpiresAtUTC:          exp,
			CreatedSeq:            seq,
		}
		tok, err := s.signer.SignGrant(child)
		if err != nil {
			return err
		}
		child.TokenHash = domain.ComputeTokenHash(tok)
		if err := tx.InsertGrant(ctx, child); err != nil {
			return err
		}
		ev := &domain.AuditEvent{
			DecisionID:          "evt_subgrant_" + grantID,
			EventType:           "SUBGRANT_ISSUED",
			TimestampUTC:        now,
			PolicyVersion:       s.cfg.PolicyVersion,
			GrantID:             child.GrantID,
			ParentGrantID:       child.ParentGrantID,
			ActorID:             child.ActorID,
			DelegatorID:         child.DelegatorID,
			Audience:            fmt.Sprintf("%v", child.Audiences),
			ActionType:          "grant.issue_subdelegated",
			ResourceID:          child.GrantID,
			AmountMinor:         child.SpendingLimit.MaxCumulativeMinor,
			Currency:            child.SpendingLimit.Currency,
			ActionDigest:        child.TokenHash,
			Decision:            domain.DecisionEvent,
			ReasonCode:          domain.ReasonGrantIssued,
			ReasonDetail:        fmt.Sprintf("sub-delegated grant issued from parent %s at depth %d", parent.GrantID, child.DelegationDepth),
			RedactedPayloadJSON: "{}",
			ReplayEnvelopeJSON:  "{}",
		}
		if err := tx.AppendAuditEvent(ctx, ev); err != nil {
			return err
		}
		issued = domain.IssuedGrant{Grant: child, Token: tok}
		return nil
	})
	if err != nil {
		return domain.IssuedGrant{}, err
	}
	s.mu.Lock()
	s.metrics.SubGrantsIssued++
	s.mu.Unlock()
	s.logger.Info("subgrant_issued", "grant_id", issued.Grant.GrantID, "parent_grant_id", issued.Grant.ParentGrantID, "depth", issued.Grant.DelegationDepth)
	return issued, nil
}

// Revoke atomically revokes a grant (cascading to all descendants), an actor, or a delegator.
func (s *PlatformService) Revoke(ctx context.Context, targetType domain.RevocationTarget, targetID, revokedBy, reason string) (domain.RevocationRecord, error) {
	if targetID == "" || revokedBy == "" || reason == "" {
		return domain.RevocationRecord{}, domain.NewDomainError(domain.ReasonInvalidInput, "target_id, revoked_by, and reason are required")
	}
	now := s.clock.Now()
	var rec domain.RevocationRecord
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		seq, err := tx.NextSequence(ctx)
		if err != nil {
			return err
		}
		rec = domain.RevocationRecord{
			RevocationID: "rev_" + uuid.NewString(),
			TargetType:   targetType,
			TargetID:     targetID,
			RevokedBy:    revokedBy,
			Reason:       reason,
			RevokedAtUTC: now,
			RevokedSeq:   seq,
		}
		if err := tx.InsertRevocation(ctx, rec); err != nil {
			return err
		}
		ev := &domain.AuditEvent{
			DecisionID:          "evt_" + rec.RevocationID,
			EventType:           "REVOCATION",
			TimestampUTC:        now,
			PolicyVersion:       s.cfg.PolicyVersion,
			GrantID:             targetID,
			ActorID:             revokedBy,
			DelegatorID:         revokedBy,
			Audience:            "aiap.control_plane",
			ActionType:          "revocation." + string(targetType),
			ResourceID:          targetID,
			ActionDigest:        domain.ComputeTokenHash(rec.RevocationID),
			Decision:            domain.DecisionEvent,
			ReasonCode:          domain.ReasonRevocationRecorded,
			ReasonDetail:        fmt.Sprintf("revoked %s %s: %s", targetType, targetID, reason),
			RedactedPayloadJSON: "{}",
			ReplayEnvelopeJSON:  "{}",
		}
		return tx.AppendAuditEvent(ctx, ev)
	})
	if err != nil {
		return domain.RevocationRecord{}, err
	}
	s.mu.Lock()
	s.metrics.RevocationsRecorded++
	s.mu.Unlock()
	s.logger.Info("revocation_recorded", "target_type", targetType, "target_id", targetID, "revoked_by", revokedBy)
	return rec, nil
}

// RegisterApproval persists a delegator-signed exact-action approval for single-use enforcement.
func (s *PlatformService) RegisterApproval(ctx context.Context, rec domain.ApprovalRecord) error {
	if rec.ApprovalID == "" || rec.GrantID == "" || rec.ActorID == "" || rec.ApproverID == "" || rec.ActionDigest == "" || rec.Nonce == "" {
		return domain.NewDomainError(domain.ReasonInvalidInput, "approval record missing required fields")
	}
	if rec.ExpiresAtUTC.Sub(rec.IssuedAtUTC) <= 0 || int64(rec.ExpiresAtUTC.Sub(rec.IssuedAtUTC).Seconds()) > s.cfg.MaxApprovalTTLSeconds {
		return domain.NewDomainError(domain.ReasonInvalidInput, "approval TTL exceeds policy max_approval_ttl_seconds (%d)", s.cfg.MaxApprovalTTLSeconds)
	}
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.InsertApproval(ctx, rec)
	})
}

// Authorize evaluates a simulated financial action under deny-by-default rules inside a serialized ACID transaction.
// Every decision (ALLOW or DENY) is recorded in the redacted hash-chained audit log.
func (s *PlatformService) Authorize(ctx context.Context, req domain.AuthorizationRequest) (domain.AuthorizationDecision, error) {
	now := s.clock.Now()
	decisionID := req.DecisionID
	if decisionID == "" {
		decisionID = "dec_" + uuid.NewString()
	}
	actionDigest := domain.ComputeActionDigest(req.Action)
	redactedJSON := domain.RedactActionPayload(req.Action, s.cfg.Redaction.RedactFields, s.cfg.Redaction.Replacement)

	// Step 1: Verify JWT signature & claims outside DB transaction (pure crypto).
	claims, tokErr := s.verifier.VerifyGrant(req.GrantToken, now)
	tokenValid := tokErr == nil
	var tokErrCode domain.ReasonCode
	var tokErrDetail string
	if tokErr != nil {
		var de *domain.DomainError
		if errors.As(tokErr, &de) {
			tokErrCode = de.Code
			tokErrDetail = de.Detail
		} else {
			tokErrCode = domain.ReasonTokenMalformed
			tokErrDetail = tokErr.Error()
		}
	}
	tokenHash := domain.ComputeTokenHash(req.GrantToken)

	var decision domain.AuthorizationDecision
	var approvalConsumed bool

	// Step 2: Execute state checks, single-use approval consumption, spending update,
	// and hash-chained audit append inside ONE serialized ACID transaction.
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var chain []domain.DelegationGrant
		var actorActive bool
		var revoked bool
		var revReason string

		if tokenValid && claims != nil {
			var err error
			chain, err = tx.GetGrantChain(ctx, claims.ID)
			if err != nil {
				return err
			}
			if len(chain) > 0 {
				if chain[0].TokenHash != tokenHash {
					tokenValid = false
					tokErrCode = domain.ReasonGrantTokenMismatch
					tokErrDetail = "presented JWT hash does not match registered grant token"
				} else {
					actor, err := tx.GetPrincipal(ctx, chain[0].ActorID)
					if err != nil {
						return err
					}
					actorActive = actor != nil && actor.Active

					// Cascading revocation check across every grant, actor, and delegator in chain.
					for _, g := range chain {
						if r, rs, err := tx.IsRevoked(ctx, domain.RevokeGrant, g.GrantID); err != nil {
							return err
						} else if r {
							revoked = true
							revReason = fmt.Sprintf("grant %s revoked: %s", g.GrantID, rs)
							break
						}
						if r, rs, err := tx.IsRevoked(ctx, domain.RevokeActor, g.ActorID); err != nil {
							return err
						} else if r {
							revoked = true
							revReason = fmt.Sprintf("actor %s revoked: %s", g.ActorID, rs)
							break
						}
						if r, rs, err := tx.IsRevoked(ctx, domain.RevokeDelegator, g.DelegatorID); err != nil {
							return err
						} else if r {
							revoked = true
							revReason = fmt.Sprintf("delegator %s revoked: %s", g.DelegatorID, rs)
							break
						}
					}
				}
			}
		}

		// Inspect exact-action approval if supplied.
		approvalProvided := req.Approval != nil
		approvalSigValid := false
		approvalAlreadyUsed := false
		var effectiveApproval *domain.ApprovalRecord

		if approvalProvided && len(chain) > 0 {
			storedApp, err := tx.GetApproval(ctx, req.Approval.ApprovalID)
			if err != nil {
				return err
			}
			// If approval was registered in store, use its persisted consumption state;
			// if submitted inline without pre-registration, we insert & consume it atomically upon ALLOW.
			if storedApp != nil {
				effectiveApproval = storedApp
				if storedApp.ConsumedAtUTC != nil {
					approvalAlreadyUsed = true
				}
			} else {
				cp := *req.Approval
				effectiveApproval = &cp
			}
			// Approver must be an active human/service delegator in the same tenant and signature must verify.
			approver, err := tx.GetPrincipal(ctx, effectiveApproval.ApproverID)
			if err != nil {
				return err
			}
			if approver != nil && approver.Active &&
				approver.PrincipalType != domain.PrincipalAgent &&
				approver.TenantID == chain[0].TenantID {
				// Also ensure approver itself is not revoked.
				if appRev, _, err := tx.IsRevoked(ctx, domain.RevokeDelegator, approver.PrincipalID); err == nil && !appRev {
					approvalSigValid = crypto.VerifyApprovalSignature(*effectiveApproval, approver.PublicKeyB64)
				}
			}
		}

		pc := s.constraints()
		pureIn := domain.PurePolicyInput{
			Constraints:         pc,
			Now:                 now,
			TokenValid:          tokenValid,
			TokenErrorCode:      tokErrCode,
			TokenErrorDetail:    tokErrDetail,
			Action:              req.Action,
			GrantChain:          chain,
			ActorActive:         actorActive,
			Revoked:             revoked,
			RevocationReason:    revReason,
			ApprovalProvided:    approvalProvided,
			ApprovalSigValid:    approvalSigValid,
			ApprovalAlreadyUsed: approvalAlreadyUsed,
			ApprovalRecord:      effectiveApproval,
		}
		res := domain.EvaluatePolicyPure(pureIn)

		// If ALLOW, perform atomic state transitions (consume approval + debit chain spend).
		if res.Decision == domain.DecisionAllow {
			if approvalProvided && effectiveApproval != nil {
				existing, err := tx.GetApproval(ctx, effectiveApproval.ApprovalID)
				if err != nil {
					return err
				}
				if existing == nil {
					if err := tx.InsertApproval(ctx, *effectiveApproval); err != nil {
						// UNIQUE(grant_id, nonce) violation catches duplicate nonce replay.
						res.Decision = domain.DecisionDeny
						res.ReasonCode = domain.ReasonApprovalAlreadyUsed
						res.ReasonDetail = fmt.Sprintf("approval %q or nonce already used", effectiveApproval.ApprovalID)
						pureIn.ApprovalAlreadyUsed = true
					}
				}
				if res.Decision == domain.DecisionAllow {
					consumed, err := tx.ConsumeApproval(ctx, effectiveApproval.ApprovalID, now, decisionID)
					if err != nil {
						return err
					}
					if !consumed {
						res.Decision = domain.DecisionDeny
						res.ReasonCode = domain.ReasonApprovalAlreadyUsed
						res.ReasonDetail = fmt.Sprintf("approval %q already consumed by concurrent request", effectiveApproval.ApprovalID)
						pureIn.ApprovalAlreadyUsed = true
					} else {
						approvalConsumed = true
					}
				}
			}
			if res.Decision == domain.DecisionAllow && req.Action.AmountMinor > 0 {
				ids := make([]string, len(chain))
				for i, g := range chain {
					ids[i] = g.GrantID
				}
				if err := tx.AddGrantSpend(ctx, ids, req.Action.AmountMinor); err != nil {
					var de *domain.DomainError
					if errors.As(err, &de) {
						res.Decision = domain.DecisionDeny
						res.ReasonCode = de.Code
						res.ReasonDetail = de.Detail
					} else {
						return err
					}
				}
			}
		}

		// Build deterministic ReplayEnvelope snapshot with redacted metadata only (zero sensitive values persisted).
		var redactedAction domain.ActionPayload
		_ = json.Unmarshal([]byte(redactedJSON), &redactedAction)
		metadataRedacted := domain.ComputeActionDigest(redactedAction) != actionDigest
		envelope := domain.ReplayEnvelope{
			PolicyVersion:        pc.PolicyVersion,
			EvaluatedAtUTC:       now,
			ClockSkewSeconds:     pc.ClockSkewSeconds,
			SupportedActionTypes: pc.SupportedActionTypes,
			SupportedCurrencies:  pc.SupportedCurrencies,
			AllowedAudiences:     pc.AllowedAudiences,
			TokenValid:           pureIn.TokenValid,
			TokenErrorCode:       pureIn.TokenErrorCode,
			TokenErrorDetail:     pureIn.TokenErrorDetail,
			Action:               redactedAction,
			MetadataRedacted:     metadataRedacted,
			OriginalActionDigest: actionDigest,
			GrantChain:           chain,
			ActorActive:          pureIn.ActorActive,
			Revoked:              pureIn.Revoked,
			RevocationReason:     pureIn.RevocationReason,
			ApprovalProvided:     pureIn.ApprovalProvided,
			ApprovalSigValid:     pureIn.ApprovalSigValid,
			ApprovalAlreadyUsed:  pureIn.ApprovalAlreadyUsed,
			ApprovalRecord:       pureIn.ApprovalRecord,
		}
		envBytes, _ := json.Marshal(envelope)

		grantID, parentGrantID, actorID, delegatorID := "", "", "", ""
		if len(chain) > 0 {
			grantID = chain[0].GrantID
			parentGrantID = chain[0].ParentGrantID
			actorID = chain[0].ActorID
			delegatorID = chain[0].DelegatorID
		} else if claims != nil {
			grantID = claims.ID
			actorID = claims.Subject
			delegatorID = claims.DelegatorID
		}
		approvalID := ""
		if req.Approval != nil {
			approvalID = req.Approval.ApprovalID
		}

		auditEv := &domain.AuditEvent{
			DecisionID:          decisionID,
			EventType:           "AUTHORIZATION",
			TimestampUTC:        now,
			PolicyVersion:       s.cfg.PolicyVersion,
			GrantID:             grantID,
			ParentGrantID:       parentGrantID,
			ActorID:             actorID,
			DelegatorID:         delegatorID,
			Audience:            req.Action.Audience,
			ActionType:          req.Action.ActionType,
			ResourceID:          req.Action.ResourceID,
			AmountMinor:         req.Action.AmountMinor,
			Currency:            req.Action.Currency,
			ActionDigest:        actionDigest,
			ApprovalID:          approvalID,
			Decision:            res.Decision,
			ReasonCode:          res.ReasonCode,
			ReasonDetail:        res.ReasonDetail,
			RedactedPayloadJSON: redactedJSON,
			ReplayEnvelopeJSON:  string(envBytes),
		}
		if err := tx.AppendAuditEvent(ctx, auditEv); err != nil {
			return err
		}

		decision = domain.AuthorizationDecision{
			DecisionID:               decisionID,
			SequenceNo:               auditEv.SequenceNo,
			Decision:                 res.Decision,
			ReasonCode:               res.ReasonCode,
			ReasonDetail:             res.ReasonDetail,
			PolicyVersion:            s.cfg.PolicyVersion,
			GrantID:                  grantID,
			ActorID:                  actorID,
			ActionDigest:             actionDigest,
			ApprovalID:               approvalID,
			RemainingCumulativeMinor: res.RemainingCumulativeMinor,
			EvaluatedAtUTC:           now,
			AuditEntryHash:           auditEv.EntryHash,
		}
		return nil
	})
	if err != nil {
		return domain.AuthorizationDecision{}, err
	}

	s.mu.Lock()
	s.metrics.TotalAuthorizations++
	if decision.Decision == domain.DecisionAllow {
		s.metrics.AllowCount++
		if approvalConsumed {
			s.metrics.ApprovalsConsumed++
		}
	} else {
		s.metrics.DenyCount++
		s.metrics.DeniesByReason[decision.ReasonCode]++
	}
	s.mu.Unlock()

	s.logger.Info("authorization_decision",
		"decision_id", decision.DecisionID,
		"sequence_no", decision.SequenceNo,
		"decision", decision.Decision,
		"reason_code", decision.ReasonCode,
		"grant_id", decision.GrantID,
		"actor_id", decision.ActorID,
		"action_type", req.Action.ActionType,
		"amount_minor", req.Action.AmountMinor,
	)
	return decision, nil
}
