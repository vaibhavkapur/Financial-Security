package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/scenarios"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "demo":
		runDemoCmd(os.Args[2:])
	case "scenarios":
		runScenariosCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("Digital Asset Custody Platform Prototype (Offline/Mock Testnet Only)")
	fmt.Println("Usage:")
	fmt.Println("  custody demo       [--policy config/default-policy.json] [--fixture data/fixtures/reference_fixture.json] [--oracle data/fixtures/expected_reference_output.json] [--out reports/baseline_reference.json]")
	fmt.Println("  custody scenarios  [--policy config/default-policy.json] [--out reports/scenario_results.json]")
}

func runDemoCmd(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	policyPath := fs.String("policy", "config/default-policy.json", "path to policy config JSON")
	fixturePath := fs.String("fixture", "data/fixtures/reference_fixture.json", "path to reference fixture JSON")
	oraclePath := fs.String("oracle", "data/fixtures/expected_reference_output.json", "path to expected reference oracle JSON")
	outPath := fs.String("out", "", "optional output path to write JSON report")
	_ = fs.Parse(args)

	report, err := scenarios.RunReferenceFixture(*policyPath, *fixturePath, *oraclePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode demo report: %v\n", err)
		os.Exit(1)
	}
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create report directory: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, append(raw, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println(string(raw))
	if !report.OracleMatched {
		os.Exit(1)
	}
}

func runScenariosCmd(args []string) {
	fs := flag.NewFlagSet("scenarios", flag.ExitOnError)
	policyPath := fs.String("policy", "config/default-policy.json", "path to policy config JSON")
	outPath := fs.String("out", "", "optional output path to write JSON scenario suite report")
	_ = fs.Parse(args)

	report, err := scenarios.RunAllScenarios(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenarios failed: %v\n", err)
		os.Exit(1)
	}

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode scenario report: %v\n", err)
		os.Exit(1)
	}
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create report directory: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, append(raw, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write scenario report: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println(string(raw))
	if !report.AllPassed {
		os.Exit(1)
	}
}
