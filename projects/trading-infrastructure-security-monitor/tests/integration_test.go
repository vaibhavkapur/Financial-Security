package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/pipeline"
)

func fixedClock() time.Time {
	return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
}

type referenceOracle struct {
	SchemaVersion   string                      `json:"schema_version"`
	OracleName      string                      `json:"oracle_name"`
	ExpectedMetrics contracts.DiagnosticMetrics `json:"expected_metrics"`
	ExpectedAlerts  []struct {
		RuleID        string `json:"rule_id"`
		SourceEventID string `json:"source_event_id"`
		Severity      string `json:"severity"`
		Actor         string `json:"actor"`
		Service       string `json:"service"`
	} `json:"expected_alerts"`
}

func TestReferenceFixtureMatchesHandCalculatedOracle(t *testing.T) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig: %v", err)
	}
	oracle, err := contracts.LoadJSONFile[referenceOracle]("../data/fixtures/reference/expected_oracle.json")
	if err != nil {
		t.Fatalf("load oracle: %v", err)
	}

	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/reference/reference_events.jsonl")
	if err != nil {
		t.Fatalf("RunFromJSONL: %v", err)
	}
	if res.Report.Metrics != oracle.ExpectedMetrics {
		t.Fatalf("metrics mismatch vs hand-calculated oracle:\ngot:  %+v\nwant: %+v", res.Report.Metrics, oracle.ExpectedMetrics)
	}
	if len(res.Report.Alerts) != len(oracle.ExpectedAlerts) {
		t.Fatalf("alert count mismatch: got %d want %d", len(res.Report.Alerts), len(oracle.ExpectedAlerts))
	}
	got := res.Report.Alerts[0]
	want := oracle.ExpectedAlerts[0]
	if got.RuleID != want.RuleID || got.SourceEventIDs[0] != want.SourceEventID || string(got.Severity) != want.Severity {
		t.Fatalf("alert mismatch vs oracle: got %+v want %+v", got, want)
	}

	// Ensure redacted secret never leaks anywhere in serialized report or OTLP telemetry
	repJSON, _ := json.Marshal(res.Report)
	otelJSON, _ := json.Marshal(res.Telemetry)
	if strings.Contains(string(repJSON), "synthetic-lab-fix-pass-01") || strings.Contains(string(otelJSON), "synthetic-lab-fix-pass-01") {
		t.Fatalf("redacted secret leaked into report or telemetry")
	}
}

func TestDomainAuthorizedDeploymentVsUnexpectedConfigScenario(t *testing.T) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig: %v", err)
	}
	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/authorized_vs_unexpected_config.jsonl")
	if err != nil {
		t.Fatalf("RunFromJSONL: %v", err)
	}
	// Expect exactly 2 alerts:
	// - sc1-005 (unauthorized direct config edit -> TISM-SIGMA-001)
	// - sc1-006 (artifact digest mismatch on deployment -> TISM-SIGMA-005)
	if res.Report.Metrics.AlertsActive != 2 {
		t.Fatalf("expected 2 active alerts, got %d: %+v", res.Report.Metrics.AlertsActive, res.Report.Alerts)
	}
	seenRules := map[string]string{}
	for _, a := range res.Report.Alerts {
		seenRules[a.RuleID] = a.SourceEventIDs[0]
	}
	if seenRules["TISM-SIGMA-001"] != "sc1-005" {
		t.Fatalf("expected TISM-SIGMA-001 on sc1-005, got %v", seenRules)
	}
	if seenRules["TISM-SIGMA-005"] != "sc1-006" {
		t.Fatalf("expected TISM-SIGMA-005 on sc1-006, got %v", seenRules)
	}
}

func TestIntegrationMissingTelemetryAndDuplicateLogs(t *testing.T) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig: %v", err)
	}
	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/missing_telemetry_and_duplicates.jsonl")
	if err != nil {
		t.Fatalf("RunFromJSONL: %v", err)
	}

	// 6 ingested lines, 2 are duplicates (1 exact ID duplicate, 1 replayed ID with identical logical payload)
	if res.Report.Metrics.EventsIngested != 6 {
		t.Fatalf("expected 6 ingested events, got %d", res.Report.Metrics.EventsIngested)
	}
	if res.Report.Metrics.EventsDeduplicated != 2 {
		t.Fatalf("expected 2 deduplicated events, got %d", res.Report.Metrics.EventsDeduplicated)
	}
	if res.Report.Metrics.EventsNormalized != 4 {
		t.Fatalf("expected 4 unique normalized events, got %d", res.Report.Metrics.EventsNormalized)
	}

	// Only 1 config_diff alert should fire (duplicates must NOT inflate alerts!)
	cfgAlerts := 0
	gapAlerts := 0
	for _, a := range res.Report.Alerts {
		if a.RuleID == "TISM-SIGMA-001" {
			cfgAlerts++
		}
		if a.RuleID == "TISM-HEALTH-001" {
			gapAlerts++
		}
		if len(a.SourceEventIDs) == 0 {
			t.Fatalf("alert %s lacks source_event_ids provenance", a.AlertID)
		}
	}
	if cfgAlerts != 1 {
		t.Fatalf("expected exactly 1 config_diff alert after deduplication, got %d", cfgAlerts)
	}

	// Missing telemetry: order_audit completely missing + auth_log has 720s gap (> 300s) -> 2 telemetry gaps
	if res.Report.Metrics.TelemetryGapsDetected != 2 || gapAlerts != 2 {
		t.Fatalf("expected 2 telemetry gaps and 2 TISM-HEALTH-001 alerts, got gaps=%d alerts=%d (%+v)",
			res.Report.Metrics.TelemetryGapsDetected, gapAlerts, res.Report.TelemetryGaps)
	}
}

func TestReproducibilityIdenticalLogicalOutputsAcrossReruns(t *testing.T) {
	p1, _ := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	p2, _ := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)

	r1, err := p1.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/synthetic_eval_dataset.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := p2.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/synthetic_eval_dataset.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	b1, _ := json.Marshal(r1.Report)
	b2, _ := json.Marshal(r2.Report)
	if string(b1) != string(b2) {
		t.Fatalf("reproducibility violation: identical inputs produced different reports")
	}
	o1, _ := json.Marshal(r1.Telemetry)
	o2, _ := json.Marshal(r2.Telemetry)
	if string(o1) != string(o2) {
		t.Fatalf("reproducibility violation: identical inputs produced different OTLP telemetry")
	}
}
