package tests

import (
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/detector"
	"trading-infrastructure-security-monitor/src/rules"
)

func loadRegressionEngine(t *testing.T) (*detector.Engine, []rules.SigmaRule) {
	t.Helper()
	policy, err := contracts.LoadJSONFile[contracts.SecurityPolicy]("../config/policy.json")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	sigmaRules, err := rules.LoadRulesDir("../config/rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := detector.NewEngine(policy, sigmaRules)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, sigmaRules
}

// TestSigmaRuleRegressionMatrix tests every Sigma rule in config/rules/ with positive, benign near-miss, and boundary events.
func TestSigmaRuleRegressionMatrix(t *testing.T) {
	eng, sigmaRules := loadRegressionEngine(t)
	if len(sigmaRules) != 5 {
		t.Fatalf("expected 5 Sigma rules in config/rules, got %d", len(sigmaRules))
	}

	inWindow := time.Date(2026, 6, 1, 10, 30, 0, 0, time.UTC)
	outOfWindow := time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)
	offHours := time.Date(2026, 6, 1, 3, 15, 0, 0, time.UTC)

	cases := []struct {
		name         string
		event        contracts.NormalizedEvent
		wantRuleID   string
		shouldTrigger bool
	}{
		// TISM-SIGMA-001: Unexpected Config Edit
		{
			name: "SIGMA-001 TP: direct edit on protected path without ticket",
			event: contracts.NormalizedEvent{
				EventID: "reg-001-tp", EventType: contracts.EventTypeConfigDiff, OccurredAt: inWindow,
				Actor: "dev-bob", Service: "risk-engine", Host: "trd-rsk-01", Action: "config_edit", Outcome: "success",
				Attributes: map[string]string{"config_path": "/etc/trading/risk-engine/limits.yaml"},
			},
			wantRuleID: "TISM-SIGMA-001", shouldTrigger: true,
		},
		{
			name: "SIGMA-001 Benign: approved CI edit inside window",
			event: contracts.NormalizedEvent{
				EventID: "reg-001-tn", EventType: contracts.EventTypeConfigDiff, OccurredAt: inWindow,
				Actor: "svc-ci-deployer", Service: "order-router", Host: "trd-ord-01", Action: "config_edit", Outcome: "success",
				ChangeTicket: "CHG-2026-1001",
				Attributes:   map[string]string{"config_path": "/etc/trading/order-router/routing.yaml"},
			},
			wantRuleID: "TISM-SIGMA-001", shouldTrigger: false,
		},
		{
			name: "SIGMA-001 Boundary: approved CI edit AFTER ticket window expires",
			event: contracts.NormalizedEvent{
				EventID: "reg-001-bnd", EventType: contracts.EventTypeConfigDiff, OccurredAt: outOfWindow,
				Actor: "svc-ci-deployer", Service: "order-router", Host: "trd-ord-01", Action: "config_edit", Outcome: "success",
				ChangeTicket: "CHG-2026-1001",
				Attributes:   map[string]string{"config_path": "/etc/trading/order-router/routing.yaml"},
			},
			wantRuleID: "TISM-SIGMA-001", shouldTrigger: true,
		},

		// TISM-SIGMA-002: Privilege Escalation
		{
			name: "SIGMA-002 TP: unauthorized role_grant",
			event: contracts.NormalizedEvent{
				EventID: "reg-002-tp", EventType: contracts.EventTypeAuthLog, OccurredAt: inWindow,
				Actor: "dev-bob", Service: "iam", Host: "trd-iam-01", Action: "role_grant", Outcome: "success", SourceIP: "10.10.1.5",
				Attributes: map[string]string{"target_role": "trading-admin"},
			},
			wantRuleID: "TISM-SIGMA-002", shouldTrigger: true,
		},
		{
			name: "SIGMA-002 Benign: failed role_grant denied by IAM",
			event: contracts.NormalizedEvent{
				EventID: "reg-002-tn", EventType: contracts.EventTypeAuthLog, OccurredAt: inWindow,
				Actor: "dev-bob", Service: "iam", Host: "trd-iam-01", Action: "role_grant", Outcome: "failure", SourceIP: "10.10.1.5",
				Attributes: map[string]string{"target_role": "trading-admin"},
			},
			wantRuleID: "TISM-SIGMA-002", shouldTrigger: false,
		},

		// TISM-SIGMA-003: Abnormal Authentication Access
		{
			name: "SIGMA-003 TP: service account interactive SSH login",
			event: contracts.NormalizedEvent{
				EventID: "reg-003-tp1", EventType: contracts.EventTypeAuthLog, OccurredAt: inWindow,
				Actor: "svc-order-router", Service: "order-router", Host: "trd-ord-01", Action: "login", Outcome: "success", SourceIP: "10.10.2.5",
				Attributes: map[string]string{"auth_method": "interactive_ssh"},
			},
			wantRuleID: "TISM-SIGMA-003", shouldTrigger: true,
		},
		{
			name: "SIGMA-003 TP: off-hours human login",
			event: contracts.NormalizedEvent{
				EventID: "reg-003-tp2", EventType: contracts.EventTypeAuthLog, OccurredAt: offHours,
				Actor: "trader-ops-1", Service: "order-router", Host: "trd-ord-01", Action: "login", Outcome: "success", SourceIP: "10.10.2.5",
				Attributes: map[string]string{"auth_method": "sso_mfa"},
			},
			wantRuleID: "TISM-SIGMA-003", shouldTrigger: true,
		},
		{
			name: "SIGMA-003 Benign: business-hours trusted IP human SSO login",
			event: contracts.NormalizedEvent{
				EventID: "reg-003-tn", EventType: contracts.EventTypeAuthLog, OccurredAt: inWindow,
				Actor: "trader-ops-1", Service: "order-router", Host: "trd-ord-01", Action: "login", Outcome: "success", SourceIP: "10.10.2.5",
				Attributes: map[string]string{"auth_method": "sso_mfa"},
			},
			wantRuleID: "TISM-SIGMA-003", shouldTrigger: false,
		},

		// TISM-SIGMA-004: Order Risk Tampering
		{
			name: "SIGMA-004 TP: kill_switch_disable without ticket",
			event: contracts.NormalizedEvent{
				EventID: "reg-004-tp", EventType: contracts.EventTypeOrderAudit, OccurredAt: inWindow,
				Actor: "dev-bob", Service: "risk-engine", Host: "trd-rsk-01", Action: "kill_switch_disable", Outcome: "success",
				Attributes: map[string]string{"order_id": "SIM-KS-1"},
			},
			wantRuleID: "TISM-SIGMA-004", shouldTrigger: true,
		},
		{
			name: "SIGMA-004 Benign: normal submit_order",
			event: contracts.NormalizedEvent{
				EventID: "reg-004-tn", EventType: contracts.EventTypeOrderAudit, OccurredAt: inWindow,
				Actor: "trader-ops-1", Service: "order-router", Host: "trd-ord-01", Action: "submit_order", Outcome: "success",
				Attributes: map[string]string{"order_id": "SIM-OK-1"},
			},
			wantRuleID: "TISM-SIGMA-004", shouldTrigger: false,
		},

		// TISM-SIGMA-005: Unauthorized Deployment
		{
			name: "SIGMA-005 TP: artifact hash mismatch under valid ticket",
			event: contracts.NormalizedEvent{
				EventID: "reg-005-tp", EventType: contracts.EventTypeDeploymentAudit, OccurredAt: inWindow,
				Actor: "svc-ci-deployer", Service: "order-router", Host: "trd-ord-01", Action: "deploy_release", Outcome: "success",
				ChangeTicket: "CHG-2026-1001",
				Attributes:   map[string]string{"artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
			},
			wantRuleID: "TISM-SIGMA-005", shouldTrigger: true,
		},
		{
			name: "SIGMA-005 Benign: verified deployment matching ticket and SHA256",
			event: contracts.NormalizedEvent{
				EventID: "reg-005-tn", EventType: contracts.EventTypeDeploymentAudit, OccurredAt: inWindow,
				Actor: "svc-ci-deployer", Service: "order-router", Host: "trd-ord-01", Action: "deploy_release", Outcome: "success",
				ChangeTicket: "CHG-2026-1001",
				Attributes:   map[string]string{"artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			},
			wantRuleID: "TISM-SIGMA-005", shouldTrigger: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := eng.Evaluate([]contracts.NormalizedEvent{tc.event}, nil, 0)
			triggered := false
			for _, a := range res.Alerts {
				if a.RuleID == tc.wantRuleID {
					triggered = true
				}
			}
			if triggered != tc.shouldTrigger {
				t.Fatalf("rule %s trigger mismatch: got %v, want %v (alerts=%+v)", tc.wantRuleID, triggered, tc.shouldTrigger, res.Alerts)
			}
		})
	}
}
