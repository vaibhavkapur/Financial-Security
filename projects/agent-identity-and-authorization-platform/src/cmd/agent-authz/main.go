package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/audit"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/enforcer"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

type fixturePrincipal struct {
	PrincipalID   string               `json:"principal_id"`
	PrincipalType domain.PrincipalType `json:"principal_type"`
	DisplayName   string               `json:"display_name"`
	TenantID      string               `json:"tenant_id"`
	KeySeed       string               `json:"key_seed"`
	Active        bool                 `json:"active"`
}

type fixtureStep struct {
	StepID                 string                 `json:"step_id"`
	Description            string                 `json:"description"`
	AdvanceSeconds         int64                  `json:"advance_seconds"`
	UseGrant               string                 `json:"use_grant"`
	Action                 domain.ActionPayload   `json:"action"`
	ApprovalMode           string                 `json:"approval_mode"`
	ApprovalID             string                 `json:"approval_id"`
	ExpectedDecision       domain.DecisionOutcome `json:"expected_decision"`
	ExpectedReasonCode     domain.ReasonCode      `json:"expected_reason_code"`
	ExpectedRemainingMinor int64                  `json:"expected_remaining_minor"`
}

type referenceFixture struct {
	FixtureVersion string              `json:"fixture_version"`
	Description    string              `json:"description"`
	Provenance     string              `json:"provenance"`
	BaseTimeUTC    string              `json:"base_time_utc"`
	SeedLabel      string              `json:"seed_label"`
	TenantID       string              `json:"tenant_id"`
	Principals     []fixturePrincipal  `json:"principals"`
	RootGrant      domain.GrantRequest `json:"root_grant"`
	SubGrant       domain.GrantRequest `json:"sub_grant"`
	Steps          []fixtureStep       `json:"steps"`
}

type stepOutcome struct {
	StepID                 string                 `json:"step_id"`
	Description            string                 `json:"description"`
	ExpectedDecision       domain.DecisionOutcome `json:"expected_decision"`
	ObservedDecision       domain.DecisionOutcome `json:"observed_decision"`
	ExpectedReasonCode     domain.ReasonCode      `json:"expected_reason_code"`
	ObservedReasonCode     domain.ReasonCode      `json:"observed_reason_code"`
	ExpectedRemainingMinor int64                  `json:"expected_remaining_minor"`
	ObservedRemainingMinor int64                  `json:"observed_remaining_minor"`
	ActionDigest           string                 `json:"action_digest"`
	AuditEntryHash         string                 `json:"audit_entry_hash"`
	Passed                 bool                   `json:"passed"`
}

type baselineReport struct {
	SchemaVersion  string                    `json:"schema_version"`
	PolicyVersion  string                    `json:"policy_version"`
	FixtureVersion string                    `json:"fixture_version"`
	RuntimeEnv     map[string]string         `json:"runtime_env"`
	Steps          []stepOutcome             `json:"steps"`
	Metrics        enforcer.MetricsSnapshot  `json:"metrics"`
	Replay         audit.ReplayReport        `json:"replay"`
	Passed         bool                      `json:"passed"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "demo":
		if err := runDemo(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
			os.Exit(1)
		}
	case "verify-fixtures":
		if err := runVerifyFixtures(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "verify-fixtures failed: %v\n", err)
			os.Exit(1)
		}
	case "evaluate":
		if err := runEvaluate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "evaluate failed: %v\n", err)
			os.Exit(1)
		}
	case "inspect-config":
		if err := runInspectConfig(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "inspect-config failed: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("Usage: agent-authz <command> [flags]")
	fmt.Println("Commands:")
	fmt.Println("  demo             Run reproducible end-to-end bounded delegation walkthrough")
	fmt.Println("  verify-fixtures  Execute reference fixture and compare against hand-calculated baseline")
	fmt.Println("  evaluate         Run seeded adversarial delegation evaluation suite")
	fmt.Println("  inspect-config   Validate a JSON configuration file under fail-closed rules")
}

func runtimeInfo() map[string]string {
	return map[string]string{
		"go_version": runtime.Version(),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
		"num_cpu":    fmt.Sprintf("%d", runtime.NumCPU()),
	}
}

func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	cfgPath := fs.String("config", "config/default.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFromFile(*cfgPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(baseTime)

	st, err := store.NewSQLiteStore(ctx, ":memory:")
	if err != nil {
		return err
	}
	defer st.Close()

	authKey := crypto.DeterministicFixtureKeyPair("auth-demo-k1", "demo-authority")
	aliceKey := crypto.DeterministicFixtureKeyPair("del-alice", "demo-alice")
	rebalKey := crypto.DeterministicFixtureKeyPair("agt-rebal", "demo-rebalancer")
	subKey := crypto.DeterministicFixtureKeyPair("agt-sub", "demo-subexec")

	svc, err := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	if err != nil {
		return err
	}

	for _, p := range []domain.Principal{
		{PrincipalID: "delegator.treasury.alice", PrincipalType: domain.PrincipalHumanDelegator, DisplayName: "Alice (Mock Treasury)", TenantID: "mock-tenant-alpha", PublicKeyB64: aliceKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.rebalancer.01", PrincipalType: domain.PrincipalAgent, DisplayName: "Mock Rebalancer Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: rebalKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
		{PrincipalID: "agent.subexec.02", PrincipalType: domain.PrincipalAgent, DisplayName: "Mock Sub-Execution Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: subKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime},
	} {
		if err := svc.RegisterPrincipal(ctx, p); err != nil {
			return err
		}
	}

	fmt.Println("=== Agent Identity & Authorization Platform (AIAP) Demo ===")
	fmt.Printf("Policy: %s | Issuer: %s | Alg: %s | Scope: Simulated Mock Actions Only\n\n", cfg.PolicyVersion, cfg.IssuerID, cfg.SigningAlgorithm)

	root, err := svc.IssueRootGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-demo-root",
		CanDelegate:           true,
		DelegatorID:           "delegator.treasury.alice",
		ActorID:               "agent.rebalancer.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-100*"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         50000,
			MaxCumulativeMinor:        100000,
			RequireApprovalAboveMinor: 15000,
		},
		TTLSeconds: 300,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[1] Issued Root Grant %s (actor=%s, cap=$1000.00, approval>$150.00, ttl=300s)\n", root.Grant.GrantID, root.Grant.ActorID)

	sub, err := svc.IssueSubDelegatedGrant(ctx, domain.GrantRequest{
		GrantID:               "grt-demo-sub",
		ParentGrantID:         root.Grant.GrantID,
		CanDelegate:           false,
		DelegatorID:           "agent.rebalancer.01",
		ActorID:               "agent.subexec.02",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit: domain.SpendingLimit{
			Currency:                  "USD",
			MaxPerActionMinor:         20000,
			MaxCumulativeMinor:        30000,
			RequireApprovalAboveMinor: 10000,
		},
		TTLSeconds: 180,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[2] Issued Attenuated Sub-Grant %s (depth=%d, actor=%s, cap=$300.00, ttl=180s)\n", sub.Grant.GrantID, sub.Grant.DelegationDepth, sub.Grant.ActorID)

	// Step 3: Within-limit payment
	d1, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		DecisionID: "dec-demo-01",
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-demo-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 10000, Currency: "USD", Metadata: map[string]string{"memo_pii": "synthetic-redacted-value"},
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("[3] Payment $100.00 -> %s (%s) remaining=$%.2f\n", d1.Decision, d1.ReasonCode, float64(d1.RemainingCumulativeMinor)/100.0)

	// Step 4: High-value payment with exact-action approval
	hiAct := domain.ActionPayload{
		ActionID: "act-demo-02", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
	}
	app, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-demo-01",
		GrantID:      root.Grant.GrantID,
		ActorID:      root.Grant.ActorID,
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(hiAct),
		Nonce:        "nonce-demo-01",
		IssuedAtUTC:  baseTime,
		ExpiresAtUTC: baseTime.Add(2 * time.Minute),
	}, aliceKey.PrivateKey)
	if err != nil {
		return err
	}

	// Tampered amount first
	tampered := hiAct
	tampered.AmountMinor = 25001
	dTamper, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		DecisionID: "dec-demo-02-tamper",
		GrantToken: root.Token,
		Action:     tampered,
		Approval:   &app,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[4] Tampered $250.01 vs $250.00 Approval -> %s (%s)\n", dTamper.Decision, dTamper.ReasonCode)

	// Exact approved action
	d2, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		DecisionID: "dec-demo-03-approved",
		GrantToken: root.Token,
		Action:     hiAct,
		Approval:   &app,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[5] Exact-Action Approved $250.00 -> %s (%s) remaining=$%.2f\n", d2.Decision, d2.ReasonCode, float64(d2.RemainingCumulativeMinor)/100.0)

	// Duplicate approval replay
	dDup, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		DecisionID: "dec-demo-04-replay",
		GrantToken: root.Token,
		Action:     hiAct,
		Approval:   &app,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[6] Reused Approval Replay -> %s (%s)\n", dDup.Decision, dDup.ReasonCode)

	// Cascading revocation
	if _, err := svc.Revoke(ctx, domain.RevokeGrant, root.Grant.GrantID, "delegator.treasury.alice", "demo emergency stop"); err != nil {
		return err
	}
	dRev, err := svc.Authorize(ctx, domain.AuthorizationRequest{
		DecisionID: "dec-demo-05-revoked",
		GrantToken: sub.Token,
		Action: domain.ActionPayload{
			ActionID: "act-demo-03", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 5000, Currency: "USD",
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("[7] Sub-Grant Action After Root Revocation -> %s (%s)\n", dRev.Decision, dRev.ReasonCode)

	// Audit Replay
	events, err := st.ListAuditEvents(ctx)
	if err != nil {
		return err
	}
	replay := audit.ReplayAuditLog(events)
	fmt.Printf("\n[8] Audit Replay: events=%d verified_decisions=%d chain_valid=%v passed=%v\n",
		replay.TotalEvents, replay.VerifiedDecisions, replay.ChainValid, replay.Passed)
	if !replay.Passed {
		return fmt.Errorf("audit replay detected mismatches: %+v", replay.Mismatches)
	}
	return nil
}

func runVerifyFixtures(args []string) error {
	fs := flag.NewFlagSet("verify-fixtures", flag.ExitOnError)
	cfgPath := fs.String("config", "config/default.json", "path to config JSON")
	fixturePath := fs.String("fixture", "data/fixtures/reference_scenario.json", "path to reference scenario JSON")
	outPath := fs.String("out", "", "optional path to write machine-readable baseline report JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFromFile(*cfgPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		return err
	}
	var fx referenceFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		return err
	}
	baseTime, err := time.Parse(time.RFC3339, fx.BaseTimeUTC)
	if err != nil {
		return err
	}
	clock := domain.NewFixedClock(baseTime)
	ctx := context.Background()

	st, err := store.NewSQLiteStore(ctx, ":memory:")
	if err != nil {
		return err
	}
	defer st.Close()

	authKey := crypto.DeterministicFixtureKeyPair("auth-ref-k1", fx.SeedLabel+"-authority")
	svc, err := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	if err != nil {
		return err
	}

	keys := make(map[string]crypto.KeyPair)
	for _, p := range fx.Principals {
		kp := crypto.DeterministicFixtureKeyPair("key-"+p.PrincipalID, p.KeySeed)
		keys[p.PrincipalID] = kp
		if err := svc.RegisterPrincipal(ctx, domain.Principal{
			PrincipalID:   p.PrincipalID,
			PrincipalType: p.PrincipalType,
			DisplayName:   p.DisplayName,
			TenantID:      p.TenantID,
			PublicKeyB64:  kp.PublicKeyBase64(),
			Active:        p.Active,
			CreatedAtUTC:  baseTime,
		}); err != nil {
			return err
		}
	}

	rootGrant, err := svc.IssueRootGrant(ctx, fx.RootGrant)
	if err != nil {
		return err
	}
	subGrant, err := svc.IssueSubDelegatedGrant(ctx, fx.SubGrant)
	if err != nil {
		return err
	}

	delegatorKey := keys[fx.RootGrant.DelegatorID]
	savedApprovals := make(map[string]domain.ApprovalRecord)
	allPassed := true
	outcomes := make([]stepOutcome, 0, len(fx.Steps))

	for _, stp := range fx.Steps {
		if stp.AdvanceSeconds > 0 {
			clock.Advance(time.Duration(stp.AdvanceSeconds) * time.Second)
		}
		grant := rootGrant
		if stp.UseGrant == "sub" {
			grant = subGrant
		}
		action := stp.Action
		var appPtr *domain.ApprovalRecord

		switch stp.ApprovalMode {
		case "valid":
			rec, err := crypto.SignApproval(domain.ApprovalRecord{
				ApprovalID:   stp.ApprovalID,
				GrantID:      grant.Grant.GrantID,
				ActorID:      grant.Grant.ActorID,
				ApproverID:   fx.RootGrant.DelegatorID,
				ActionDigest: domain.ComputeActionDigest(action),
				Nonce:        "nonce-" + stp.ApprovalID,
				IssuedAtUTC:  clock.Now(),
				ExpiresAtUTC: clock.Now().Add(2 * time.Minute),
			}, delegatorKey.PrivateKey)
			if err != nil {
				return err
			}
			savedApprovals[stp.ApprovalID] = rec
			appPtr = &rec
		case "reuse_previous":
			rec := savedApprovals[stp.ApprovalID]
			appPtr = &rec
		case "altered_amount_plus_one":
			rec, err := crypto.SignApproval(domain.ApprovalRecord{
				ApprovalID:   stp.ApprovalID,
				GrantID:      grant.Grant.GrantID,
				ActorID:      grant.Grant.ActorID,
				ApproverID:   fx.RootGrant.DelegatorID,
				ActionDigest: domain.ComputeActionDigest(action),
				Nonce:        "nonce-" + stp.ApprovalID,
				IssuedAtUTC:  clock.Now(),
				ExpiresAtUTC: clock.Now().Add(2 * time.Minute),
			}, delegatorKey.PrivateKey)
			if err != nil {
				return err
			}
			action.AmountMinor++
			appPtr = &rec
		}

		dec, err := svc.Authorize(ctx, domain.AuthorizationRequest{
			DecisionID: "dec-" + stp.StepID,
			GrantToken: grant.Token,
			Action:     action,
			Approval:   appPtr,
		})
		if err != nil {
			return err
		}
		passed := dec.Decision == stp.ExpectedDecision &&
			dec.ReasonCode == stp.ExpectedReasonCode &&
			dec.RemainingCumulativeMinor == stp.ExpectedRemainingMinor
		if !passed {
			allPassed = false
		}
		outcomes = append(outcomes, stepOutcome{
			StepID:                 stp.StepID,
			Description:            stp.Description,
			ExpectedDecision:       stp.ExpectedDecision,
			ObservedDecision:       dec.Decision,
			ExpectedReasonCode:     stp.ExpectedReasonCode,
			ObservedReasonCode:     dec.ReasonCode,
			ExpectedRemainingMinor: stp.ExpectedRemainingMinor,
			ObservedRemainingMinor: dec.RemainingCumulativeMinor,
			ActionDigest:           dec.ActionDigest,
			AuditEntryHash:         dec.AuditEntryHash,
			Passed:                 passed,
		})
	}

	events, err := st.ListAuditEvents(ctx)
	if err != nil {
		return err
	}
	replay := audit.ReplayAuditLog(events)
	if !replay.Passed {
		allPassed = false
	}

	rep := baselineReport{
		SchemaVersion:  cfg.SchemaVersion,
		PolicyVersion:  cfg.PolicyVersion,
		FixtureVersion: fx.FixtureVersion,
		RuntimeEnv:     runtimeInfo(),
		Steps:          outcomes,
		Metrics:        svc.Metrics(),
		Replay:         replay,
		Passed:         allPassed,
	}
	encoded, _ := json.MarshalIndent(rep, "", "  ")
	if *outPath != "" {
		if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	fmt.Println(string(encoded))
	if !allPassed {
		return fmt.Errorf("one or more reference fixture assertions failed")
	}
	return nil
}

func runEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	cfgPath := fs.String("config", "config/default.json", "path to config JSON")
	seedFlag := fs.Int64("seed", 0, "override random seed (0 uses config.evaluation.random_seed)")
	outPath := fs.String("out", "", "optional path to write adversarial report JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFromFile(*cfgPath)
	if err != nil {
		return err
	}
	seed := cfg.Evaluation.RandomSeed
	if *seedFlag != 0 {
		seed = *seedFlag
	}
	rep, err := audit.RunAdversarialSuite(context.Background(), cfg, seed)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(rep, "", "  ")
	if *outPath != "" {
		if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	fmt.Println(string(encoded))
	if !rep.Passed {
		return fmt.Errorf("adversarial evaluation failed: %d/%d passed, replay=%v", rep.PassedCases, rep.TotalCases, rep.ReplayVerified)
	}
	return nil
}

func runInspectConfig(args []string) error {
	fs := flag.NewFlagSet("inspect-config", flag.ExitOnError)
	cfgPath := fs.String("config", "config/default.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFromFile(*cfgPath)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(encoded))
	return nil
}
