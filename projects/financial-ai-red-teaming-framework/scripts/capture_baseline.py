#!/usr/bin/env python3
"""Capture or refresh the pinned baseline evaluation report in reports/baseline_evaluation.json."""

from __future__ import annotations

import argparse
from pathlib import Path

from fin_redteam.harness import EvaluationHarness
from fin_redteam.models import AgentMode


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture pinned baseline evaluation output.")
    parser.add_argument("--config", default="config/harness_config.json")
    parser.add_argument("--output", default="reports/baseline_evaluation.json")
    args = parser.parse_args()

    harness = EvaluationHarness(Path(args.config))
    ok, _oracle_report, issues = harness.verify_reference_oracle()
    if not ok:
        raise SystemExit(f"Reference oracle verification failed before baseline capture: {issues}")

    guarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_GUARDED)
    if not guarded.summary.within_tolerances:
        raise SystemExit("Refusing to capture baseline: guarded run did not meet tolerances.")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(guarded.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(f"Captured baseline {guarded.run_id} -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
