package audit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/enforcer"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

// AdversarialCaseResult records the outcome of one adversarial test vector.
type AdversarialCaseResult struct {
	CaseID          string            `json:"case_id"`
	Category        string            `json:"category"`
	Description     string            `json:"description"`
	ExpectedCode    domain.ReasonCode `json:"expected_code"`
	ObservedCode    domain.ReasonCode `json:"observed_code"`
	Blocked         bool              `json:"blocked"`
	Passed          bool              `json:"passed"`
	Detail          string            `json:"detail"`
}

// AdversarialReport summarizes the deterministic adversarial delegation evaluation suite.
type AdversarialReport struct {
	SchemaVersion      string                  `json:"schema_version"`
	PolicyVersion      string                  `json:"policy_version"`
	RandomSeed         int64                   `json:"random_seed"`
	EvaluatedAtUTC     string                  `json:"evaluated_at_utc"`
	TotalCases         int                     `json:"total_cases"`
	PassedCases        int                     `json:"passed_cases"`
	BlockedAttacks     int                     `json:"blocked_attacks"`
	FuzzMutationsRun   int                     `json:"fuzz_mutations_run"`
	FuzzMutationsBlocked int                   `json:"fuzz_mutations_blocked"`
	ReplayVerified     bool                    `json:"replay_verified"`
	Passed             bool                    `json:"passed"`
	Cases              []AdversarialCaseResult `json:"cases"`
}

func extractReasonCode(err error) domain.ReasonCode {
	if err == nil {
		return ""
	}
	var de *domain.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return domain.ReasonInvalidInput
}

// RunAdversarialSuite runs a deterministic seeded suite of delegation escalation,
// token tamper, approval replay, revocation race, and payload mutation attacks.
func RunAdversarialSuite(ctx context.Context, cfg config.Config, seed int64) (AdversarialReport, error) {
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(baseTime)

	st, err := store.NewSQLiteStore(ctx, ":memory:")
	if err != nil {
		return AdversarialReport{}, err
	}
	defer st.Close()

	authKey := crypto.DeterministicFixtureKeyPair("auth-k1", fmt.Sprintf("authority-%d", seed))
	delegatorKey := crypto.DeterministicFixtureKeyPair("del-alice", fmt.Sprintf("alice-%d", seed))
	agentKey := crypto.DeterministicFixtureKeyPair("agt-pay", fmt.Sprintf("agent-pay-%d", seed))
	subAgentKey := crypto.DeterministicFixtureKeyPair("agt-sub", fmt.Sprintf("agent-sub-%d", seed))
	rogueTenantKey := crypto.DeterministicFixtureKeyPair("agt-rogue", fmt.Sprintf("agent-rogue-%d", seed))

	svc, err := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	if err != nil {
		return AdversarialReport{}, err
	}

	principals := []domain.Principal{
		{PrincipalID: "delegator.treasury.alice", PrincipalType: domain.PrincipalHumanDelegator, DisplayName: "Alice (Mock Treasury)", TenantID: "mock-tenant-alpha", PublicKeyB64: delegatorKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.payments.01", PrincipalType: domain.PrincipalAgent, DisplayName: "Mock Payments Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: agentKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.subexec.02", PrincipalType: domain.PrincipalAgent, DisplayName: "Mock Sub-Execution Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: subAgentKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.other.tenant", PrincipalType: domain.PrincipalAgent, DisplayName: "Mock Beta Tenant Agent", TenantID: "mock-tenant-beta", PublicKeyB64: rogueTenantKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
	}
	for _, p := range principals {
		if err := svc.RegisterPrincipal(ctx, p); err != nil {
			return AdversarialReport{}, err
		}
	}

	rootGrant, err := svc.IssueRootGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-adv-root",
		CanDelegate:           true,
		DelegatorID:           "delegator.treasury.alice",
		ActorID:               "agent.payments.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-100*"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         50000,
			MaxCumulativeMinor:        100000,
			RequireApprovalAboveMinor: 10000,
		},
		TTLSeconds: 300,
	})
	if err != nil {
		return AdversarialReport{}, err
	}

	nonDelegableGrant, err := svc.IssueRootGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-adv-nodelegate",
		CanDelegate:           false,
		DelegatorID:           "delegator.treasury.alice",
		ActorID:               "agent.payments.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         10000,
			MaxCumulativeMinor:        20000,
			RequireApprovalAboveMinor: 5000,
		},
		TTLSeconds: 300,
	})
	if err != nil {
		return AdversarialReport{}, err
	}

	report := AdversarialReport{
		SchemaVersion:  cfg.SchemaVersion,
		PolicyVersion:  cfg.PolicyVersion,
		RandomSeed:     seed,
		EvaluatedAtUTC: baseTime.Format(time.RFC3339),
		Cases:          []AdversarialCaseResult{},
	}

	addCase := func(id, cat, desc string, expected, observed domain.ReasonCode, blocked bool, detail string) {
		passed := blocked && observed == expected
		report.TotalCases++
		if blocked {
			report.BlockedAttacks++
		}
		if passed {
			report.PassedCases++
		}
		report.Cases = append(report.Cases, AdversarialCaseResult{
			CaseID:       id,
			Category:     cat,
			Description:  desc,
			ExpectedCode: expected,
			ObservedCode: observed,
			Blocked:      blocked,
			Passed:       passed,
			Detail:       detail,
		})
	}

	// 1. Delegation escalation: widen scope to broader wildcard
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-scope",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-*"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         rootGrant.Grant.SpendingLimit,
		TTLSeconds:            120,
	})
	addCase("ADV-01", "delegation_escalation", "Sub-delegation attempts to widen resource scope from mock-acct-100* to mock-acct-*",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 2. Delegation escalation: raise max_per_action_minor
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-limit",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         75000,
			MaxCumulativeMinor:        100000,
			RequireApprovalAboveMinor: 10000,
		},
		TTLSeconds: 120,
	})
	addCase("ADV-02", "delegation_escalation", "Sub-delegation attempts to raise max_per_action_minor above parent cap",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 3. Delegation escalation: weaken approval threshold
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-approval",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         50000,
			MaxCumulativeMinor:        50000,
			RequireApprovalAboveMinor: 25000,
		},
		TTLSeconds: 120,
	})
	addCase("ADV-03", "delegation_escalation", "Sub-delegation attempts to raise require_approval_above_minor to bypass approvals",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 4. Delegation escalation: extend expiry beyond parent
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-ttl",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         rootGrant.Grant.SpendingLimit,
		TTLSeconds:            600,
	})
	addCase("ADV-04", "delegation_escalation", "Sub-delegation attempts to extend grant expiry past parent TTL",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 5. Delegation escalation: add unlisted audience
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-aud",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api", "mock-settlement-engine"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         rootGrant.Grant.SpendingLimit,
		TTLSeconds:            120,
	})
	addCase("ADV-05", "delegation_escalation", "Sub-delegation attempts to widen audience to mock-settlement-engine",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 6. Delegation escalation: drop counterparty restriction
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-cp",
		ParentGrantID:         rootGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: nil,
		SpendingLimit:         rootGrant.Grant.SpendingLimit,
		TTLSeconds:            120,
	})
	addCase("ADV-06", "delegation_escalation", "Sub-delegation attempts to drop parent counterparty allowlist",
		domain.ReasonDelegationEscalation, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 7. Delegation from non-delegable grant
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-esc-nodelegate",
		ParentGrantID:         nonDelegableGrant.Grant.GrantID,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         nonDelegableGrant.Grant.SpendingLimit,
		TTLSeconds:            120,
	})
	addCase("ADV-07", "delegation_escalation", "Sub-delegation attempted from non-delegable parent grant",
		domain.ReasonDelegationNotAllowed, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 8. Delegation depth exceeded (depth 0 -> 1 -> 2 -> 3 blocked when max_delegation_depth=2)
	child1, err := svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-adv-d1",
		ParentGrantID:         rootGrant.Grant.GrantID,
		CanDelegate:           true,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 20000, MaxCumulativeMinor: 40000, RequireApprovalAboveMinor: 10000},
		TTLSeconds:            200,
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	child2, err := svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-adv-d2",
		ParentGrantID:         child1.Grant.GrantID,
		CanDelegate:           true,
		DelegatorID:           "agent.subexec.02",
		ActorID:               "agent.payments.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 10000, MaxCumulativeMinor: 20000, RequireApprovalAboveMinor: 5000},
		TTLSeconds:            150,
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	_, err = svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-adv-d3-overflow",
		ParentGrantID:         child2.Grant.GrantID,
		CanDelegate:           false,
		DelegatorID:           "agent.payments.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 5000, MaxCumulativeMinor: 5000, RequireApprovalAboveMinor: 5000},
		TTLSeconds:            100,
	})
	addCase("ADV-08", "delegation_escalation", "Delegation chain depth 3 exceeds policy max_delegation_depth=2",
		domain.ReasonDelegationDepthExceeded, extractReasonCode(err), err != nil, fmt.Sprintf("%v", err))

	// 9. JWT algorithm downgrade (HS256 signed with public key bytes)
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": cfg.IssuerID, "sub": "agent.payments.01", "jti": rootGrant.Grant.GrantID,
		"exp": baseTime.Add(5 * time.Minute).Unix(), "iat": baseTime.Unix(),
	})
	downgradedJWT, _ := hsTok.SignedString([]byte(authKey.PublicKey))
	decAlg, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: downgradedJWT,
		Action: domain.ActionPayload{
			ActionID: "act-adv-alg", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-09", "crypto_downgrade", "Forged HS256 JWT attempting algorithm confusion attack",
		domain.ReasonTokenInvalidAlg, decAlg.ReasonCode, decAlg.Decision == domain.DecisionDeny, decAlg.ReasonDetail)

	// 10. Audience mismatch
	decAud, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: rootGrant.Token,
		Action: domain.ActionPayload{
			ActionID: "act-adv-aud", ActionType: "payment.initiate", Audience: "mock-settlement-engine",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-10", "confused_deputy", "Action directed at audience outside grant aud claim",
		domain.ReasonAudienceMismatch, decAud.ReasonCode, decAud.Decision == domain.DecisionDeny, decAud.ReasonDetail)

	// 11. Exact-action approval with altered amount (+1 minor unit)
	approvedAction := domain.ActionPayload{
		ActionID: "act-adv-amt", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
	}
	appRec, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-adv-01",
		GrantID:      rootGrant.Grant.GrantID,
		ActorID:      "agent.payments.01",
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(approvedAction),
		Nonce:        "nonce-adv-01",
		IssuedAtUTC:  baseTime,
		ExpiresAtUTC: baseTime.Add(2 * time.Minute),
	}, delegatorKey.PrivateKey)
	if err != nil {
		return AdversarialReport{}, err
	}
	alteredAction := approvedAction
	alteredAction.AmountMinor = 25001
	decAlt, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: rootGrant.Token,
		Action:     alteredAction,
		Approval:   &appRec,
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-11", "payload_tampering", "Approved payment amount altered from 25000 to 25001 minor units",
		domain.ReasonApprovalPayloadMismatch, decAlt.ReasonCode, decAlt.Decision == domain.DecisionDeny, decAlt.ReasonDetail)

	// 12. Agent self-approval forgery
	selfApp, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-adv-self",
		GrantID:      rootGrant.Grant.GrantID,
		ActorID:      "agent.payments.01",
		ApproverID:   "agent.payments.01",
		ActionDigest: domain.ComputeActionDigest(approvedAction),
		Nonce:        "nonce-adv-self",
		IssuedAtUTC:  baseTime,
		ExpiresAtUTC: baseTime.Add(2 * time.Minute),
	}, agentKey.PrivateKey)
	if err != nil {
		return AdversarialReport{}, err
	}
	decSelf, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: rootGrant.Token,
		Action:     approvedAction,
		Approval:   &selfApp,
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-12", "approval_forgery", "Agent attempts to self-sign approval for its own high-value action",
		domain.ReasonApprovalInvalidSig, decSelf.ReasonCode, decSelf.Decision == domain.DecisionDeny, decSelf.ReasonDetail)

	// 13. Seeded deterministic payload mutation fuzz burst (20 mutations against signed approval)
	rng := rand.New(rand.NewSource(seed))
	fuzzBlocked := 0
	const fuzzCount = 20
	for i := 0; i < fuzzCount; i++ {
		mut := approvedAction
		switch i % 4 {
		case 0:
			mut.AmountMinor = approvedAction.AmountMinor + int64(rng.Intn(500)+1)
		case 1:
			mut.ResourceID = fmt.Sprintf("mock-acct-100%d", rng.Intn(8)+2)
		case 2:
			mut.ActionID = fmt.Sprintf("act-mut-%d", rng.Intn(100000))
		case 3:
			mut.Metadata = map[string]string{"note": base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("mut-%d", i)))}
		}
		d, err := svc.Authorize(ctx, domain.AuthorizationRequest{
			GrantToken: rootGrant.Token,
			Action:     mut,
			Approval:   &appRec,
		})
		if err != nil {
			return AdversarialReport{}, err
		}
		if d.Decision == domain.DecisionDeny && d.ReasonCode == domain.ReasonApprovalPayloadMismatch {
			fuzzBlocked++
		}
	}
	report.FuzzMutationsRun = fuzzCount
	report.FuzzMutationsBlocked = fuzzBlocked
	addCase("ADV-13", "seeded_payload_fuzz", fmt.Sprintf("%d seeded payload mutations against exact-action approval", fuzzCount),
		domain.ReasonApprovalPayloadMismatch, domain.ReasonApprovalPayloadMismatch, fuzzBlocked == fuzzCount,
		fmt.Sprintf("blocked %d/%d payload mutations", fuzzBlocked, fuzzCount))

	// 14. Concurrent duplicate approval race (10 goroutines submitting the exact valid approval)
	var dupAllows, dupDenies int
	var dupMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := svc.Authorize(ctx, domain.AuthorizationRequest{
				GrantToken: rootGrant.Token,
				Action:     approvedAction,
				Approval:   &appRec,
			})
			if err != nil {
				return
			}
			dupMu.Lock()
			if d.Decision == domain.DecisionAllow {
				dupAllows++
			} else if d.ReasonCode == domain.ReasonApprovalAlreadyUsed {
				dupDenies++
			}
			dupMu.Unlock()
		}()
	}
	wg.Wait()
	addCase("ADV-14", "duplicate_approval_race", "10 concurrent requests reusing the same exact-action approval",
		domain.ReasonApprovalAlreadyUsed, domain.ReasonApprovalAlreadyUsed, dupAllows == 1 && dupDenies == 9,
		fmt.Sprintf("allows=%d (expected 1), denied_already_used=%d (expected 9)", dupAllows, dupDenies))

	// 15. Cascading revocation: revoke root grant -> child2 at depth 2 must immediately be denied
	if _, err := svc.Revoke(ctx, domain.RevokeGrant, rootGrant.Grant.GrantID, "delegator.treasury.alice", "adversarial test cascading revoke"); err != nil {
		return AdversarialReport{}, err
	}
	decCascade, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: child2.Token,
		Action: domain.ActionPayload{
			ActionID: "act-adv-cascade", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-15", "cascading_revocation", "Revoking root grant immediately invalidates depth-2 sub-delegated grant",
		domain.ReasonGrantRevoked, decCascade.ReasonCode, decCascade.Decision == domain.DecisionDeny, decCascade.ReasonDetail)

	// 16. Expired grant check (advance clock past nonDelegableGrant expiry)
	clock.Advance(301 * time.Second)
	decExp, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		GrantToken: nonDelegableGrant.Token,
		Action: domain.ActionPayload{
			ActionID: "act-adv-exp", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		return AdversarialReport{}, err
	}
	addCase("ADV-16", "expired_grant", "Action submitted 1 second after grant expiration",
		domain.ReasonGrantExpired, decExp.ReasonCode, decExp.Decision == domain.DecisionDeny, decExp.ReasonDetail)

	// Verify audit hash chain and deterministic replay of the entire adversarial run!
	events, err := st.ListAuditEvents(ctx)
	if err != nil {
		return AdversarialReport{}, err
	}
	replay := ReplayAuditLog(events)
	report.ReplayVerified = replay.Passed && replay.ChainValid
	report.Passed = report.PassedCases == report.TotalCases && report.ReplayVerified
	return report, nil
}
