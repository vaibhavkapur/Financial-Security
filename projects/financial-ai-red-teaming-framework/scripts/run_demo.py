#!/usr/bin/env python3
"""Reproducible end-to-end demo for the Financial AI Red Teaming Framework."""

from __future__ import annotations

import argparse
from pathlib import Path

from fin_redteam.harness import EvaluationHarness
from fin_redteam.models import AgentMode, EvaluationReport
from fin_redteam.reporting import (
    build_regression_report,
    compare_against_baseline,
    render_regression_markdown,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Financial AI Red Teaming Framework demo.")
    parser.add_argument(
        "--config",
        default="config/harness_config.json",
        help="Path to pinned harness configuration JSON.",
    )
    parser.add_argument(
        "--verify-baseline",
        action="store_true",
        help="Fail with non-zero exit code if results deviate from reports/baseline_evaluation.json.",
    )
    parser.add_argument(
        "--write-reports",
        action="store_true",
        help="Persist latest evaluation and regression reports to reports/.",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    harness = EvaluationHarness(config_path)

    oracle_ok, oracle_report, oracle_issues = harness.verify_reference_oracle()
    print(f"[Oracle] verified={oracle_ok} run_id={oracle_report.run_id} issues={oracle_issues}")
    if not oracle_ok:
        return 2

    unguarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_UNGUARDED)
    guarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_GUARDED)

    print(
        f"[Unguarded Reference] run_id={unguarded.run_id} "
        f"ASR={unguarded.summary.attack_success_rate:.1%} "
        f"FRR={unguarded.summary.false_refusal_rate:.1%} "
        f"canary_leaks={unguarded.summary.canary_leak_count}"
    )
    print(
        f"[Guarded Harness]     run_id={guarded.run_id} "
        f"ASR={guarded.summary.attack_success_rate:.1%} "
        f"FRR={guarded.summary.false_refusal_rate:.1%} "
        f"canary_leaks={guarded.summary.canary_leak_count} "
        f"passed={guarded.summary.passed_scenarios}/{guarded.summary.total_scenarios}"
    )

    baseline_path = harness.base_dir / "reports" / "baseline_evaluation.json"
    baseline_report = None
    if baseline_path.exists():
        baseline_report = EvaluationReport.model_validate_json(
            baseline_path.read_text(encoding="utf-8")
        )
        diffs = compare_against_baseline(guarded, baseline_report)
        print(f"[Baseline Check] discrepancies={len(diffs)}")
        if args.verify_baseline and diffs:
            for d in diffs:
                print(f"  REGRESSION: {d}")
            return 2

    reg_report = build_regression_report(
        guarded_report=guarded,
        unguarded_report=unguarded,
        baseline_report=baseline_report,
        config_rel_path=args.config,
    )
    print(
        f"[Regression Report]   status={reg_report.overall_status} "
        f"mitigated={reg_report.mitigated_findings} open={reg_report.open_findings} "
        f"regressions={reg_report.regressions_detected}"
    )

    if args.write_reports:
        reports_dir = harness.base_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "latest_evaluation.json").write_text(
            guarded.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (reports_dir / "unguarded_evaluation.json").write_text(
            unguarded.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (reports_dir / "regression_report.json").write_text(
            reg_report.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (reports_dir / "regression_report.md").write_text(
            render_regression_markdown(reg_report, guarded), encoding="utf-8"
        )
        print(f"[Artifacts Written]   {reports_dir}")

    return 0 if guarded.summary.within_tolerances else 2


if __name__ == "__main__":
    raise SystemExit(main())
