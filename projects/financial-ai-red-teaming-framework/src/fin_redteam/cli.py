"""Command-line interface for running red-team evaluations, oracle checks, replays, and diffs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fin_redteam.errors import RedTeamError
from fin_redteam.harness import EvaluationHarness
from fin_redteam.models import AgentMode, EvaluationReport
from fin_redteam.reporting import (
    build_regression_report,
    compare_against_baseline,
    render_regression_markdown,
)


def _write_json(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")


def _cmd_run(args: argparse.Namespace) -> int:
    harness = EvaluationHarness(Path(args.config))
    mode = AgentMode(args.mode) if args.mode else None
    report = harness.run_suite(agent_mode=mode, seed=args.seed)

    if args.output:
        _write_json(Path(args.output), report.model_dump_json(indent=2))

    if args.regression_dir:
        reg_dir = Path(args.regression_dir)
        unguarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_UNGUARDED, seed=args.seed)
        baseline = None
        if args.baseline and Path(args.baseline).exists():
            baseline = EvaluationReport.model_validate_json(
                Path(args.baseline).read_text(encoding="utf-8")
            )
        reg = build_regression_report(
            guarded_report=report,
            unguarded_report=unguarded,
            baseline_report=baseline,
            config_rel_path=args.config,
        )
        _write_json(reg_dir / "regression_report.json", reg.model_dump_json(indent=2))
        md_path = reg_dir / "regression_report.md"
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_regression_markdown(reg, report), encoding="utf-8")

    print(
        json.dumps(
            {
                "run_id": report.run_id,
                "agent_mode": report.agent_mode.value,
                "passed_scenarios": report.summary.passed_scenarios,
                "total_scenarios": report.summary.total_scenarios,
                "attack_success_rate": report.summary.attack_success_rate,
                "false_refusal_rate": report.summary.false_refusal_rate,
                "canary_leak_count": report.summary.canary_leak_count,
                "within_tolerances": report.summary.within_tolerances,
            },
            indent=2,
        )
    )
    return 0 if report.summary.within_tolerances else 2


def _cmd_verify_oracle(args: argparse.Namespace) -> int:
    harness = EvaluationHarness(Path(args.config))
    ok, report, discrepancies = harness.verify_reference_oracle()
    print(
        json.dumps(
            {
                "oracle_verified": ok,
                "run_id": report.run_id,
                "attack_success_rate": report.summary.attack_success_rate,
                "false_refusal_rate": report.summary.false_refusal_rate,
                "discrepancies": discrepancies,
            },
            indent=2,
        )
    )
    return 0 if ok else 2


def _cmd_run_scenario(args: argparse.Namespace) -> int:
    harness = EvaluationHarness(Path(args.config))
    mode = AgentMode(args.mode) if args.mode else None
    verdict = harness.run_single_by_id(args.scenario_id, agent_mode=mode)
    print(verdict.model_dump_json(indent=2))
    return 0 if verdict.passed or mode == AgentMode.DETERMINISTIC_UNGUARDED else 2


def _cmd_replay(args: argparse.Namespace) -> int:
    prev_path = Path(args.previous)
    if not prev_path.exists():
        print(f"Error: previous report not found: {prev_path}", file=sys.stderr)
        return 1
    previous = EvaluationReport.model_validate_json(prev_path.read_text(encoding="utf-8"))
    harness = EvaluationHarness(Path(args.config))
    replayed = harness.run_suite(
        agent_mode=previous.agent_mode,
        seed=previous.runtime_metadata.seed,
    )
    discrepancies = compare_against_baseline(replayed, previous)
    logical_match = (
        len(discrepancies) == 0
        and replayed.run_id == previous.run_id
        and replayed.diagnostic_counters == previous.diagnostic_counters
    )
    print(
        json.dumps(
            {
                "replay_match": logical_match,
                "previous_run_id": previous.run_id,
                "replayed_run_id": replayed.run_id,
                "discrepancies": discrepancies,
            },
            indent=2,
        )
    )
    return 0 if logical_match else 2


def _cmd_diff(args: argparse.Namespace) -> int:
    baseline = EvaluationReport.model_validate_json(Path(args.baseline).read_text(encoding="utf-8"))
    candidate = EvaluationReport.model_validate_json(
        Path(args.candidate).read_text(encoding="utf-8")
    )
    discrepancies = compare_against_baseline(candidate, baseline)
    print(
        json.dumps(
            {
                "baseline_run_id": baseline.run_id,
                "candidate_run_id": candidate.run_id,
                "regressions_found": len(discrepancies),
                "discrepancies": discrepancies,
            },
            indent=2,
        )
    )
    return 0 if not discrepancies else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fin-redteam",
        description="Offline Financial AI Red Teaming Framework CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run evaluation suite and optionally generate reports.")
    p_run.add_argument("--config", default="config/harness_config.json")
    p_run.add_argument("--mode", choices=[m.value for m in AgentMode], default=None)
    p_run.add_argument("--seed", type=int, default=None)
    p_run.add_argument("--output", default=None)
    p_run.add_argument("--regression-dir", default=None)
    p_run.add_argument("--baseline", default="reports/baseline_evaluation.json")
    p_run.set_defaults(func=_cmd_run)

    p_oracle = sub.add_parser("verify-oracle", help="Verify deterministic reference oracle.")
    p_oracle.add_argument("--config", default="config/harness_config.json")
    p_oracle.set_defaults(func=_cmd_verify_oracle)

    p_scn = sub.add_parser("run-scenario", help="Run a single scenario by ID for reproduction.")
    p_scn.add_argument("--config", default="config/harness_config.json")
    p_scn.add_argument("--scenario-id", required=True)
    p_scn.add_argument("--mode", choices=[m.value for m in AgentMode], default=None)
    p_scn.set_defaults(func=_cmd_run_scenario)

    p_replay = sub.add_parser("replay", help="Replay a previous evaluation report deterministically.")
    p_replay.add_argument("--config", default="config/harness_config.json")
    p_replay.add_argument("--previous", required=True)
    p_replay.set_defaults(func=_cmd_replay)

    p_diff = sub.add_parser("diff", help="Diff a candidate evaluation against a baseline report.")
    p_diff.add_argument("--baseline", required=True)
    p_diff.add_argument("--candidate", required=True)
    p_diff.set_defaults(func=_cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RedTeamError as exc:
        print(f"RedTeamError: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
