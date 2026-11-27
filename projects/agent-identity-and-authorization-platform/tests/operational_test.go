package tests

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

func TestOperational_MissingAndInvalidConfigurationFailsClosed(t *testing.T) {
	// 1. Missing config file
	if _, err := config.LoadFromFile("/nonexistent/path/config.json"); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("expected ERR_INVALID_CONFIG for missing file, got %v", err)
	}

	// 2. Malformed JSON
	tmpDir := t.TempDir()
	badJSON := filepath.Join(tmpDir, "bad.json")
	_ = os.WriteFile(badJSON, []byte(`{"schema_version": `), 0o644)
	if _, err := config.LoadFromFile(badJSON); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("expected ERR_INVALID_CONFIG for malformed JSON, got %v", err)
	}

	// 3. Unknown field rejected
	unknownField := filepath.Join(tmpDir, "unknown.json")
	_ = os.WriteFile(unknownField, []byte(`{"unknown_knob": true}`), 0o644)
	if _, err := config.LoadFromFile(unknownField); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("expected ERR_INVALID_CONFIG for unknown field, got %v", err)
	}

	// 4. Unsafe config variants rejected
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"deny_by_default_false", func(c *config.Config) { c.DenyByDefault = false }},
		{"unsupported_alg_HS256", func(c *config.Config) { c.SigningAlgorithm = "HS256" }},
		{"default_ttl_gt_max", func(c *config.Config) { c.DefaultGrantTTLSeconds = c.MaxGrantTTLSeconds + 1 }},
		{"unsupported_storage_driver", func(c *config.Config) { c.Storage.Driver = "mysql" }},
		{"empty_audiences", func(c *config.Config) { c.AllowedAudiences = nil }},
		{"excessive_delegation_depth", func(c *config.Config) { c.MaxDelegationDepth = 10 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.DefaultConfig()
			tc.mutate(&c)
			if err := c.Validate(); !errors.Is(err, config.ErrInvalidConfig) {
				t.Fatalf("%s: expected ERR_INVALID_CONFIG, got %v", tc.name, err)
			}
		})
	}

	// 5. Default shipped config/default.json must load cleanly.
	if _, err := config.LoadFromFile("../config/default.json"); err != nil {
		t.Fatalf("expected config/default.json to be valid, got %v", err)
	}
}

func TestOperational_UnsupportedDomainInputsRejected(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()

	// Bare wildcard '*' scope forbidden
	_, err := h.svc.IssueRootGrant(h.ctx, domain.GrantRequest{
		DelegatorID: "delegator.treasury.alice",
		ActorID:     "agent.rebalancer.01",
		TenantID:    "mock-tenant-alpha",
		Audiences:   []string{"mock-treasury-api"},
		Scopes:      []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "*"}},
		SpendingLimit: domain.SpendingLimit{
			Currency: "USD", MaxPerActionMinor: 1000, MaxCumulativeMinor: 5000, RequireApprovalAboveMinor: 1000,
		},
		TTLSeconds: 60,
	})
	var de *domain.DomainError
	if !errors.As(err, &de) || de.Code != domain.ReasonInvalidInput {
		t.Fatalf("expected ERR_INVALID_INPUT for bare wildcard scope, got %v", err)
	}

	// Self-delegation forbidden
	_, err = h.svc.IssueRootGrant(h.ctx, domain.GrantRequest{
		DelegatorID: "delegator.treasury.alice",
		ActorID:     "delegator.treasury.alice",
		TenantID:    "mock-tenant-alpha",
		Audiences:   []string{"mock-treasury-api"},
		Scopes:      []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		SpendingLimit: domain.SpendingLimit{
			Currency: "USD", MaxPerActionMinor: 1000, MaxCumulativeMinor: 5000, RequireApprovalAboveMinor: 1000,
		},
		TTLSeconds: 60,
	})
	if !errors.As(err, &de) || de.Code != domain.ReasonInvalidInput {
		t.Fatalf("expected ERR_INVALID_INPUT for self-delegation, got %v", err)
	}

	// Agent cannot issue a root grant
	_, err = h.svc.IssueRootGrant(h.ctx, domain.GrantRequest{
		DelegatorID: "agent.rebalancer.01",
		ActorID:     "agent.subexec.02",
		TenantID:    "mock-tenant-alpha",
		Audiences:   []string{"mock-treasury-api"},
		Scopes:      []domain.Scope{{ActionType: "payment.initiate", ResourcePattern: "mock-acct-1001"}},
		SpendingLimit: domain.SpendingLimit{
			Currency: "USD", MaxPerActionMinor: 1000, MaxCumulativeMinor: 5000, RequireApprovalAboveMinor: 1000,
		},
		TTLSeconds: 60,
	})
	if !errors.As(err, &de) || de.Code != domain.ReasonDelegationNotAllowed {
		t.Fatalf("expected ERR_DELEGATION_NOT_ALLOWED for agent issuing root grant, got %v", err)
	}
}
