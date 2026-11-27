package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"trading-infrastructure-security-monitor/src/containment"
	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/pipeline"
	"trading-infrastructure-security-monitor/src/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "validate-config":
		err = cmdValidateConfig(args)
	case "run":
		err = cmdRun(args)
	case "replay":
		err = cmdReplay(args)
	case "evaluate":
		err = cmdEvaluate(args)
	case "demo":
		err = cmdDemo(args)
	default:
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tism %s error: %v\n", cmd, err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Trading Infrastructure Security Monitor (TISM) — Defensive Lab CLI")
	fmt.Println("Usage:")
	fmt.Println("  tism validate-config --config config/monitor_config.json")
	fmt.Println("  tism run --config <cfg> --input <events.jsonl> [--output <report.json>] [--otel-out <otel.json>] [--replay-out <norm.jsonl>]")
	fmt.Println("  tism replay --config <cfg> --input <norm.jsonl> [--output <report.json>]")
	fmt.Println("  tism evaluate --config <cfg> --input <events.jsonl> --ground-truth <gt.json> [--output <eval.json>]")
	fmt.Println("  tism demo --config <cfg> --input <events.jsonl> [--output <report.json>] [--otel-out <otel.json>]")
}

func deterministicClock() time.Time {
	return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
}

func cmdValidateConfig(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/monitor_config.json", "Path to monitor config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := pipeline.LoadFromConfig(*cfgPath, nil, deterministicClock)
	if err != nil {
		return err
	}
	fmt.Printf("Configuration valid: env=%s rules=%d containment_mode=%s live_containment=%v\n",
		p.Config.Environment, len(p.Rules), p.Config.ContainmentMode, p.Config.LiveContainmentEnabled)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/monitor_config.json", "Path to monitor config JSON")
	inputPath := fs.String("input", "", "Path to input raw events JSONL")
	outputPath := fs.String("output", "", "Optional path to write JSON RunReport")
	otelPath := fs.String("otel-out", "", "Optional path to write OTLP/JSON telemetry export")
	replayPath := fs.String("replay-out", "", "Optional path to write normalized events JSONL for replay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		return fmt.Errorf("--input is required")
	}
	p, err := pipeline.LoadFromConfig(*cfgPath, nil, deterministicClock)
	if err != nil {
		return err
	}
	res, err := p.RunFromJSONL(context.Background(), *inputPath)
	if err != nil {
		return err
	}
	if *replayPath != "" {
		if err := store.WriteNormalizedJSONL(*replayPath, res.NormalizedEvents); err != nil {
			return err
		}
	}
	if *otelPath != "" {
		if err := writeJSON(*otelPath, res.Telemetry); err != nil {
			return err
		}
	}
	if *outputPath != "" {
		if err := writeJSON(*outputPath, res.Report); err != nil {
			return err
		}
	}
	printSummary(res.Report)
	return nil
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/monitor_config.json", "Path to monitor config JSON")
	inputPath := fs.String("input", "", "Path to normalized events JSONL")
	outputPath := fs.String("output", "", "Optional path to write JSON RunReport")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		return fmt.Errorf("--input is required")
	}
	p, err := pipeline.LoadFromConfig(*cfgPath, nil, deterministicClock)
	if err != nil {
		return err
	}
	events, err := store.LoadNormalizedJSONL(*inputPath)
	if err != nil {
		return err
	}
	res, err := p.ReplayNormalized(context.Background(), events, *inputPath)
	if err != nil {
		return err
	}
	if *outputPath != "" {
		if err := writeJSON(*outputPath, res.Report); err != nil {
			return err
		}
	}
	printSummary(res.Report)
	return nil
}

func cmdEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/monitor_config.json", "Path to monitor config JSON")
	inputPath := fs.String("input", "", "Path to synthetic dataset JSONL")
	gtPath := fs.String("ground-truth", "", "Path to ground truth JSON")
	outputPath := fs.String("output", "", "Optional path to write EvaluationReport JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *gtPath == "" {
		return fmt.Errorf("--input and --ground-truth are required")
	}
	p, err := pipeline.LoadFromConfig(*cfgPath, nil, deterministicClock)
	if err != nil {
		return err
	}
	gt, err := contracts.LoadJSONFile[pipeline.GroundTruthDataset](*gtPath)
	if err != nil {
		return err
	}
	res, err := p.RunFromJSONL(context.Background(), *inputPath)
	if err != nil {
		return err
	}
	eval := pipeline.Evaluate(res.Report, gt)
	if *outputPath != "" {
		if err := writeJSON(*outputPath, eval); err != nil {
			return err
		}
	}
	fmt.Printf("Evaluation [%s]: TP=%d FP=%d FN=%d Recall=%.4f Precision=%.4f F1=%.4f Traced=%v LiveContainment=%d\n",
		gt.DatasetName, eval.TruePositives, eval.FalsePositives, eval.FalseNegatives,
		eval.Recall, eval.Precision, eval.F1Score, eval.AllAlertsTraced, eval.LiveContainmentCount)
	return nil
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/monitor_config.json", "Path to monitor config JSON")
	inputPath := fs.String("input", "data/fixtures/scenarios/synthetic_eval_dataset.jsonl", "Path to demo events JSONL")
	outputPath := fs.String("output", "", "Optional path to write reviewed RunReport JSON")
	otelPath := fs.String("otel-out", "", "Optional path to write OTLP/JSON telemetry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := pipeline.LoadFromConfig(*cfgPath, nil, deterministicClock)
	if err != nil {
		return err
	}
	res, err := p.RunFromJSONL(context.Background(), *inputPath)
	if err != nil {
		return err
	}

	// Simulate human reviewer workflow on the generated proposals (strictly simulation_only)
	reviewTime := deterministicClock().Add(5 * time.Minute)
	for _, prop := range res.Report.ContainmentProposals {
		if _, err := p.Simulator.ReviewProposal(prop.ProposalID, "sec-reviewer-alice", "approve", "Reviewed correlated evidence and blast radius", reviewTime); err != nil {
			return err
		}
		if prop.RequiredApprovals >= 2 {
			if _, err := p.Simulator.ReviewProposal(prop.ProposalID, "sec-reviewer-bob", "approve", "Dual-control approval for critical severity dry-run simulation", reviewTime.Add(time.Minute)); err != nil {
				return err
			}
		}
		if _, err := p.Simulator.SimulateApproved(prop.ProposalID, "soc-lead-carol", reviewTime.Add(2*time.Minute)); err != nil {
			return err
		}
	}

	// Update report with post-review proposals and verified audit chain
	res.Report.ContainmentProposals = p.Simulator.Proposals()
	res.Report.ReviewerAuditLog = p.Simulator.AuditLog()
	if err := containment.VerifyAuditChain(res.Report.ReviewerAuditLog); err != nil {
		return err
	}

	if *outputPath != "" {
		if err := writeJSON(*outputPath, res.Report); err != nil {
			return err
		}
	}
	if *otelPath != "" {
		if err := writeJSON(*otelPath, res.Telemetry); err != nil {
			return err
		}
	}
	printSummary(res.Report)
	fmt.Printf("Containment Simulation Review: %d proposal(s) reviewed & simulated (live_executed=false); audit_chain=%d records VERIFIED\n",
		len(res.Report.ContainmentProposals), len(res.Report.ReviewerAuditLog))
	return nil
}

func printSummary(r contracts.RunReport) {
	fmt.Printf("RunID=%s | Ingested=%d Normalized=%d Dedup=%d Invalid=%d RedactedFields=%d | Gaps=%d | Alerts=%d (Active=%d Suppressed=%d) | Cases=%d | Proposals=%d (Live=%v)\n",
		r.Metadata.RunID,
		r.Metrics.EventsIngested,
		r.Metrics.EventsNormalized,
		r.Metrics.EventsDeduplicated,
		r.Metrics.EventsInvalid,
		r.Metrics.FieldsRedacted,
		r.Metrics.TelemetryGapsDetected,
		r.Metrics.AlertsTotal,
		r.Metrics.AlertsActive,
		r.Metrics.AlertsSuppressed,
		r.Metrics.CasesCreated,
		r.Metrics.ProposalsCreated,
		r.Metadata.LiveContainment,
	)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
