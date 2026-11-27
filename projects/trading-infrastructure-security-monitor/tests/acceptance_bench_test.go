package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/normalizer"
	"trading-infrastructure-security-monitor/src/pipeline"
	"trading-infrastructure-security-monitor/src/store"
)

// TestAcceptanceCriteriaSyntheticEvaluation verifies all project-specific acceptance criteria in plan.md section 5.
func TestAcceptanceCriteriaSyntheticEvaluation(t *testing.T) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		t.Fatalf("LoadFromConfig: %v", err)
	}
	gt, err := contracts.LoadJSONFile[pipeline.GroundTruthDataset]("../data/fixtures/scenarios/synthetic_eval_ground_truth.json")
	if err != nil {
		t.Fatalf("load ground truth: %v", err)
	}

	res, err := p.RunFromJSONL(context.Background(), "../data/fixtures/scenarios/synthetic_eval_dataset.jsonl")
	if err != nil {
		t.Fatalf("RunFromJSONL: %v", err)
	}
	eval := pipeline.Evaluate(res.Report, gt)

	// AC1: Synthetic detection recall and false-positive counts reported & verified
	if eval.Recall != 1.0 {
		t.Fatalf("expected 100%% synthetic recall, got %.4f (missing=%v)", eval.Recall, eval.MissingExpectedAlerts)
	}
	if eval.FalsePositives != 0 {
		t.Fatalf("expected 0 false positives, got %d (unexpected=%v)", eval.FalsePositives, eval.UnexpectedAlerts)
	}
	if eval.ObservedCaseCount != eval.ExpectedCaseCount {
		t.Fatalf("expected %d correlated cases, got %d", eval.ExpectedCaseCount, eval.ObservedCaseCount)
	}

	// AC2: Every alert traces to source events
	if !eval.AllAlertsTraced {
		t.Fatalf("acceptance failure: at least one alert does not trace to source_event_ids")
	}

	// AC3: No automatic live containment
	if eval.LiveContainmentCount != 0 || res.Report.Metadata.LiveContainment {
		t.Fatalf("acceptance failure: live containment detected")
	}

	// Secret redaction check across entire report and telemetry
	repBytes, _ := json.Marshal(res.Report)
	otelBytes, _ := json.Marshal(res.Telemetry)
	for _, secret := range []string{"syntheticSecretToken9876543210", "tism_sim_AABBCCDD11223344"} {
		if strings.Contains(string(repBytes), secret) || strings.Contains(string(otelBytes), secret) {
			t.Fatalf("secret %q leaked into report or telemetry", secret)
		}
	}
}

func BenchmarkPipelineSyntheticEval(b *testing.B) {
	p, err := pipeline.LoadFromConfig("../config/monitor_config.json", nil, fixedClock)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Store = store.NewMemoryStore()
		if _, err := p.RunFromJSONL(ctx, "../data/fixtures/scenarios/synthetic_eval_dataset.jsonl"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedactionEngine(b *testing.B) {
	redPolicy, err := contracts.LoadJSONFile[contracts.RedactionPolicy]("../config/redaction_policy.json")
	if err != nil {
		b.Fatal(err)
	}
	red, err := normalizer.NewRedactor(redPolicy)
	if err != nil {
		b.Fatal(err)
	}
	payload := map[string]any{
		"config_path":  "/etc/trading/risk-engine/limits.yaml",
		"fix_password": "synthetic-fix-password-1234",
		"diff_summary": "Authorization: Bearer syntheticBearerToken998877665544 and key tism_sim_1122334455667788",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = red.RedactMap("payload", payload)
	}
}
