package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/audit"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/enforcer"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

func BenchmarkGrantSignAndVerify(b *testing.B) {
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	kp := crypto.DeterministicFixtureKeyPair("bench-k1", "bench-authority")
	signer := crypto.GrantSigner{Key: kp}
	verifier := crypto.GrantVerifier{
		IssuerID:         "aiap-authority.mock.local",
		DefaultPublicKey: kp.PublicKey,
		ClockSkewSeconds: 0,
	}
	grant := domain.DelegationGrant{
		GrantID:               "grt-bench-01",
		RootGrantID:           "grt-bench-01",
		IssuerID:              "aiap-authority.mock.local",
		DelegatorID:           "delegator.treasury.alice",
		ActorID:               "agent.rebalancer.01",
		TenantID:              "mock-tenant-alpha",
		Audiences:             []string{"mock-treasury-api"},
		Scopes:                []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-100*"}},
		AllowedCounterparties: []string{"mock-cp-clearing-a"},
		SpendingLimit:         domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 50000, MaxCumulativeMinor: 1000000, RequireApprovalAboveMinor: 15000},
		IssuedAtUTC:           baseTime,
		NotBeforeUTC:          baseTime,
		ExpiresAtUTC:          baseTime.Add(5 * time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tok, err := signer.SignGrant(grant)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := verifier.VerifyGrant(tok, baseTime); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorizeEndToEnd(b *testing.B) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(baseTime)

	st, err := store.NewSQLiteStore(ctx, ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()

	authKey := crypto.DeterministicFixtureKeyPair("auth-bench", "bench-auth")
	delKey := crypto.DeterministicFixtureKeyPair("del-bench", "bench-del")
	agtKey := crypto.DeterministicFixtureKeyPair("agt-bench", "bench-agt")
	svc, err := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	if err != nil {
		b.Fatal(err)
	}
	_ = svc.RegisterPrincipal(ctx, domain.Principal{PrincipalID: "delegator.treasury.alice", PrincipalType: domain.PrincipalHumanDelegator, DisplayName: "Alice", TenantID: "mock-tenant-alpha", PublicKeyB64: delKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime})
	_ = svc.RegisterPrincipal(ctx, domain.Principal{PrincipalID: "agent.rebalancer.01", PrincipalType: domain.PrincipalAgent, DisplayName: "Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: agtKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime})

	root, err := svc.IssueRootGrant(ctx, domain.GrantRequest{
		GrantID: "grt-bench-e2e", DelegatorID: "delegator.treasury.alice", ActorID: "agent.rebalancer.01",
		TenantID: "mock-tenant-alpha", Audiences: []string{"mock-treasury-api"},
		Scopes: []domain.Scope{{ActionType: "account.read", ResourcePattern: "mock-acct-100*"}},
		SpendingLimit: domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 0, MaxCumulativeMinor: 0, RequireApprovalAboveMinor: 0},
		TTLSeconds: 300,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec, err := svc.Authorize(ctx, domain.AuthorizationRequest{
			GrantToken: root.Token,
			Action: domain.ActionPayload{
				ActionID:   fmt.Sprintf("act-bench-%d", i),
				ActionType: "account.read",
				Audience:   "mock-treasury-api",
				TenantID:   "mock-tenant-alpha",
				ResourceID: "mock-acct-1001",
			},
		})
		if err != nil || dec.Decision != domain.DecisionAllow {
			b.Fatalf("unexpected result: %+v err=%v", dec, err)
		}
	}
}

func BenchmarkAuditReplay100Events(b *testing.B) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	baseTime := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(baseTime)

	st, err := store.NewSQLiteStore(ctx, ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()

	authKey := crypto.DeterministicFixtureKeyPair("auth-r", "replay-auth")
	delKey := crypto.DeterministicFixtureKeyPair("del-r", "replay-del")
	agtKey := crypto.DeterministicFixtureKeyPair("agt-r", "replay-agt")
	svc, _ := enforcer.NewPlatformService(cfg, st, authKey, clock, nil)
	_ = svc.RegisterPrincipal(ctx, domain.Principal{PrincipalID: "delegator.treasury.alice", PrincipalType: domain.PrincipalHumanDelegator, DisplayName: "Alice", TenantID: "mock-tenant-alpha", PublicKeyB64: delKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime})
	_ = svc.RegisterPrincipal(ctx, domain.Principal{PrincipalID: "agent.rebalancer.01", PrincipalType: domain.PrincipalAgent, DisplayName: "Agent", TenantID: "mock-tenant-alpha", PublicKeyB64: agtKey.PublicKeyBase64(), Active: true, CreatedAtUTC: baseTime})
	root, _ := svc.IssueRootGrant(ctx, domain.GrantRequest{
		GrantID: "grt-bench-replay", DelegatorID: "delegator.treasury.alice", ActorID: "agent.rebalancer.01",
		TenantID: "mock-tenant-alpha", Audiences: []string{"mock-treasury-api"},
		Scopes: []domain.Scope{{ActionType: "account.read", ResourcePattern: "mock-acct-100*"}},
		SpendingLimit: domain.SpendingLimit{Currency: "USD", MaxPerActionMinor: 0, MaxCumulativeMinor: 0, RequireApprovalAboveMinor: 0},
		TTLSeconds: 300,
	})
	for i := 0; i < 100; i++ {
		_, _ = svc.Authorize(ctx, domain.AuthorizationRequest{
			GrantToken: root.Token,
			Action: domain.ActionPayload{
				ActionID: fmt.Sprintf("act-r-%d", i), ActionType: "account.read", Audience: "mock-treasury-api",
				TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001",
			},
		})
	}
	events, err := st.ListAuditEvents(ctx)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep := audit.ReplayAuditLog(events)
		if !rep.Passed {
			b.Fatalf("replay failed: %+v", rep)
		}
	}
}
