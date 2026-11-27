package pipeline

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/store"
)

func TestPipelineEndToEndAndReplayDeterminism(t *testing.T) {
	fixedClock := func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	p1, err := LoadFromConfig("../../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig failed: %v", err)
	}

	raw := []contracts.RawEvent{
		{
			EventID:      "e-1",
			EventType:    contracts.EventTypeDeploymentAudit,
			Timestamp:    "2026-06-01T10:10:00Z",
			Actor:        "svc-ci-deployer",
			Service:      "order-router",
			Host:         "trd-ord-01",
			Action:       "deploy_release",
			Outcome:      "success",
			ChangeTicket: "CHG-2026-1001",
			Payload: map[string]any{
				"artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		{
			EventID:   "e-2",
			EventType: contracts.EventTypeConfigDiff,
			Timestamp: "2026-06-01T10:12:00Z",
			Actor:     "dev-rogue",
			Service:   "risk-engine",
			Host:      "trd-rsk-01",
			Action:    "config_edit",
			Outcome:   "success",
			Payload: map[string]any{
				"config_path":  "/etc/trading/risk-engine/limits.yaml",
				"fix_password": "synthetic-secret-value",
			},
		},
		{
			EventID:   "e-3",
			EventType: contracts.EventTypeAuthLog,
			Timestamp: "2026-06-01T10:11:00Z",
			Actor:     "dev-rogue",
			Service:   "risk-engine",
			Host:      "trd-rsk-01",
			Action:    "login",
			Outcome:   "success",
			SourceIP:  "198.51.100.44",
		},
		{
			EventID:   "e-4",
			EventType: contracts.EventTypeOrderAudit,
			Timestamp: "2026-06-01T10:13:00Z",
			Actor:     "dev-rogue",
			Service:   "risk-engine",
			Host:      "trd-rsk-01",
			Action:    "risk_limit_override",
			Outcome:   "success",
			Payload:   map[string]any{"order_id": "ORD-SIM-99", "symbol": "AAPL"},
		},
	}

	res1, err := p1.RunRawEvents(context.Background(), raw)
	if err != nil {
		t.Fatalf("RunRawEvents failed: %v", err)
	}
	if res1.Report.Metrics.AlertsActive != 3 {
		t.Fatalf("expected 3 active alerts (auth + config_diff + order_audit), got %d", res1.Report.Metrics.AlertsActive)
	}
	if res1.Report.Metrics.CasesCreated != 1 {
		t.Fatalf("expected 1 correlated case for dev-rogue, got %d", res1.Report.Metrics.CasesCreated)
	}
	if res1.Report.Metrics.FieldsRedacted != 1 {
		t.Fatalf("expected 1 redacted field, got %d", res1.Report.Metrics.FieldsRedacted)
	}

	// Write normalized JSONL and replay on a fresh pipeline instance
	replayFile := filepath.Join(t.TempDir(), "normalized.jsonl")
	if err := store.WriteNormalizedJSONL(replayFile, res1.NormalizedEvents); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadNormalizedJSONL(replayFile)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := LoadFromConfig("../../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := p2.ReplayNormalized(context.Background(), loaded, replayFile)
	if err != nil {
		t.Fatal(err)
	}

	a1, _ := json.Marshal(res1.Report.Alerts)
	a2, _ := json.Marshal(res2.Report.Alerts)
	if string(a1) != string(a2) {
		t.Fatalf("replay alerts diverged:\nrun1: %s\nrun2: %s", string(a1), string(a2))
	}
	c1, _ := json.Marshal(res1.Report.Cases)
	c2, _ := json.Marshal(res2.Report.Cases)
	if string(c1) != string(c2) {
		t.Fatalf("replay cases diverged:\nrun1: %s\nrun2: %s", string(c1), string(c2))
	}
}
