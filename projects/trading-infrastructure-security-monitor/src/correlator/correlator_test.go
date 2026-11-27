package correlator

import (
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

func TestCorrelatorGroupsRelatedAlertsWithStableIDAndProvenance(t *testing.T) {
	corr := NewCorrelator(900)
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	alerts := []contracts.Alert{
		{
			AlertID:        "ALT-1",
			RuleID:         "TISM-SIGMA-003",
			Category:       "auth_log",
			Severity:       contracts.SeverityHigh,
			OccurredAt:     base,
			Actor:          "compromised-dev",
			Service:        "risk-engine",
			Host:           "trd-rsk-01",
			Summary:        "untrusted login",
			SourceEventIDs: []string{"evt-1"},
			Evidence:       map[string]string{"session_id": "sess-9"},
		},
		{
			AlertID:        "ALT-2",
			RuleID:         "TISM-SIGMA-001",
			Category:       "config_diff",
			Severity:       contracts.SeverityHigh,
			OccurredAt:     base.Add(2 * time.Minute),
			Actor:          "compromised-dev",
			Service:        "risk-engine",
			Host:           "trd-rsk-01",
			Summary:        "direct config edit",
			SourceEventIDs: []string{"evt-2"},
			Evidence:       map[string]string{},
		},
		{
			AlertID:        "ALT-3",
			RuleID:         "TISM-SIGMA-004",
			Category:       "order_audit",
			Severity:       contracts.SeverityCritical,
			OccurredAt:     base.Add(4 * time.Minute),
			Actor:          "compromised-dev",
			Service:        "order-router",
			Host:           "trd-ord-01",
			Summary:        "risk limit override",
			SourceEventIDs: []string{"evt-3"},
			Evidence:       map[string]string{},
		},
		{
			AlertID:        "ALT-SUP",
			RuleID:         "TISM-SIGMA-003",
			Category:       "auth_log",
			Severity:       contracts.SeverityHigh,
			OccurredAt:     base.Add(1 * time.Minute),
			Actor:          "ops-oncall-dana",
			Service:        "order-router",
			Host:           "trd-ord-01",
			Suppressed:     true,
			SourceEventIDs: []string{"evt-4"},
			Evidence:       map[string]string{},
		},
	}

	cases1 := corr.Correlate(alerts)
	cases2 := corr.Correlate(alerts)

	if len(cases1) != 1 {
		t.Fatalf("expected 1 correlated case (suppressed excluded), got %d", len(cases1))
	}
	c := cases1[0]
	if c.CaseID != cases2[0].CaseID {
		t.Fatalf("case ID is not deterministic: %s vs %s", c.CaseID, cases2[0].CaseID)
	}
	if c.Severity != contracts.SeverityCritical {
		t.Fatalf("expected escalated severity critical, got %s", c.Severity)
	}
	if len(c.SourceEventIDs) != 3 {
		t.Fatalf("expected 3 traced source_event_ids, got %v", c.SourceEventIDs)
	}
	if len(c.AlertIDs) != 3 {
		t.Fatalf("expected 3 alert_ids, got %v", c.AlertIDs)
	}
}
