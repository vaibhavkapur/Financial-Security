package detector

import (
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/rules"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	policy, err := contracts.LoadJSONFile[contracts.SecurityPolicy]("../../config/policy.json")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	sigmaRules, err := rules.LoadRulesDir("../../config/rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := NewEngine(policy, sigmaRules)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// Required domain test: Authorized deployment vs unexpected config edit
func TestAuthorizedDeploymentVsUnexpectedConfigEdit(t *testing.T) {
	eng := loadTestEngine(t)

	events := []contracts.NormalizedEvent{
		// 1. Authorized deployment matching CHG-2026-1001, actor, artifact SHA256, and time window
		{
			EventID:      "evt-auth-deploy-1",
			EventType:    contracts.EventTypeDeploymentAudit,
			OccurredAt:   time.Date(2026, 6, 1, 10, 30, 0, 0, time.UTC),
			Actor:        "svc-ci-deployer",
			Service:      "order-router",
			Host:         "trd-ord-01",
			Action:       "deploy_release",
			Outcome:      "success",
			ChangeTicket: "CHG-2026-1001",
			Attributes: map[string]string{
				"artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		// 2. Authorized config diff under CHG-2026-1001 by svc-ci-deployer on approved path
		{
			EventID:      "evt-auth-cfg-1",
			EventType:    contracts.EventTypeConfigDiff,
			OccurredAt:   time.Date(2026, 6, 1, 10, 31, 0, 0, time.UTC),
			Actor:        "svc-ci-deployer",
			Service:      "order-router",
			Host:         "trd-ord-01",
			Action:       "config_edit",
			Outcome:      "success",
			ChangeTicket: "CHG-2026-1001",
			Attributes: map[string]string{
				"config_path": "/etc/trading/order-router/routing.yaml",
			},
		},
		// 3. Unexpected direct config edit on risk-engine without change ticket
		{
			EventID:    "evt-unauth-cfg-1",
			EventType:  contracts.EventTypeConfigDiff,
			OccurredAt: time.Date(2026, 6, 1, 10, 40, 0, 0, time.UTC),
			Actor:      "dev-rogue-1",
			Service:    "risk-engine",
			Host:       "trd-rsk-01",
			Action:     "config_edit",
			Outcome:    "success",
			Attributes: map[string]string{
				"config_path": "/etc/trading/risk-engine/limits.yaml",
			},
		},
		// 4. Config edit by svc-ci-deployer using CHG-2026-1001 but on UNAPPROVED path (must alert!)
		{
			EventID:      "evt-scope-creep-cfg-1",
			EventType:    contracts.EventTypeConfigDiff,
			OccurredAt:   time.Date(2026, 6, 1, 10, 45, 0, 0, time.UTC),
			Actor:        "svc-ci-deployer",
			Service:      "order-router",
			Host:         "trd-ord-01",
			Action:       "config_edit",
			Outcome:      "success",
			ChangeTicket: "CHG-2026-1001",
			Attributes: map[string]string{
				"config_path": "/etc/trading/order-router/secret_override.yaml",
			},
		},
	}

	res := eng.Evaluate(events, nil, 0)
	if len(res.Alerts) != 2 {
		t.Fatalf("expected exactly 2 alerts (unauth edit + scope-creep edit), got %d: %+v", len(res.Alerts), res.Alerts)
	}
	for _, a := range res.Alerts {
		if a.RuleID != "TISM-SIGMA-001" {
			t.Fatalf("expected TISM-SIGMA-001, got %s", a.RuleID)
		}
		if a.SourceEventIDs[0] == "evt-auth-deploy-1" || a.SourceEventIDs[0] == "evt-auth-cfg-1" {
			t.Fatalf("authorized event unexpectedly alerted: %+v", a)
		}
	}
}

func TestBruteForceAndSuppressionExpiration(t *testing.T) {
	eng := loadTestEngine(t)

	// Off-hours login by ops-oncall-dana on order-router BEFORE suppression expiry (2026-06-05) -> suppressed
	// Off-hours login by ops-oncall-dana on order-router AFTER suppression expiry (2026-06-06) -> NOT suppressed (fail-closed)
	events := []contracts.NormalizedEvent{
		{
			EventID:    "evt-sup-active",
			EventType:  contracts.EventTypeAuthLog,
			OccurredAt: time.Date(2026, 6, 2, 2, 0, 0, 0, time.UTC),
			Actor:      "ops-oncall-dana",
			Service:    "order-router",
			Host:       "trd-ord-01",
			Action:     "login",
			Outcome:    "success",
			SourceIP:   "10.10.5.10",
		},
		{
			EventID:    "evt-sup-expired",
			EventType:  contracts.EventTypeAuthLog,
			OccurredAt: time.Date(2026, 6, 6, 2, 0, 0, 0, time.UTC),
			Actor:      "ops-oncall-dana",
			Service:    "order-router",
			Host:       "trd-ord-01",
			Action:     "login",
			Outcome:    "success",
			SourceIP:   "10.10.5.10",
		},
	}

	res := eng.Evaluate(events, nil, 0)
	if len(res.Alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(res.Alerts))
	}
	if !res.Alerts[0].Suppressed || res.Alerts[0].SuppressionID != "SUP-2026-001" {
		t.Fatalf("expected first alert suppressed by SUP-2026-001, got %+v", res.Alerts[0])
	}
	if res.Alerts[1].Suppressed {
		t.Fatalf("expected second alert AFTER expiry NOT to be suppressed (fail closed), got %+v", res.Alerts[1])
	}
}
