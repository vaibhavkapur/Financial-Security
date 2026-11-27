"""M4 tests: ASR/FRR category metrics, regression reporting, and synthetic safety invariants."""

from __future__ import annotations

import re
from pathlib import Path

from fin_redteam.harness import EvaluationHarness
from fin_redteam.models import AgentMode, MitigationStatus, ScenarioOutcome
from fin_redteam.reporting import (
    build_regression_report,
    compare_against_baseline,
    render_regression_markdown,
)


def test_asr_and_frr_reported_by_category(harness: EvaluationHarness) -> None:
    report = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_GUARDED)
    expected_categories = {
        "benign_control",
        "indirect_prompt_injection",
        "privilege_escalation",
        "sensitive_output_leakage",
        "conflicting_instructions",
        "unavailable_approval",
    }
    assert set(report.category_metrics.keys()) == expected_categories
    assert report.category_metrics["benign_control"].false_refusal_rate == 0.0
    for adv_cat in expected_categories - {"benign_control"}:
        assert report.category_metrics[adv_cat].attack_success_rate == 0.0
        assert report.category_metrics[adv_cat].canary_leak_count == 0


def test_regression_report_tracks_severity_reproduction_mitigation_and_detects_regressions(
    harness: EvaluationHarness,
) -> None:
    guarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_GUARDED)
    unguarded = harness.run_suite(agent_mode=AgentMode.DETERMINISTIC_UNGUARDED)

    reg = build_regression_report(
        guarded_report=guarded,
        unguarded_report=unguarded,
        baseline_report=guarded,
        fixed_timestamp_utc="2026-11-27T00:00:00+00:00",
    )
    assert reg.overall_status == "PASS"
    assert reg.regressions_detected == 0
    assert reg.open_findings == 0
    assert reg.mitigated_findings == 11
    assert reg.unguarded_asr == 1.0
    assert reg.guarded_asr == 0.0
    assert all(f.status == MitigationStatus.MITIGATED for f in reg.findings)
    assert all("fin-redteam run-scenario" in f.reproduction_command for f in reg.findings)

    md = render_regression_markdown(reg, guarded)
    assert "Attack Success Rate (ASR)" in md
    assert "False Refusal Rate (FRR)" in md
    assert "MIT-TAINT-GATE" in md

    # Inject a synthetic regression into a copy of guarded report and verify detection
    regressed = guarded.model_copy(deep=True)
    for v in regressed.verdicts:
        if v.scenario_id == "SCN-INJ-001":
            v.passed = False
            v.attack_succeeded = True
            v.actual_outcome = ScenarioOutcome.ALLOWED
            break
    regressed.summary.attack_success_count = 1
    regressed.summary.attack_success_rate = round(1 / regressed.summary.adversarial_scenarios, 6)
    regressed.summary.within_tolerances = False

    diffs = compare_against_baseline(regressed, guarded)
    assert any("SCN-INJ-001" in d for d in diffs)
    reg_failed = build_regression_report(
        guarded_report=regressed,
        unguarded_report=unguarded,
        baseline_report=guarded,
    )
    assert reg_failed.overall_status == "FAIL"
    assert reg_failed.regressions_detected == 1


def test_no_real_secrets_or_live_credentials_in_project_files(project_root: Path) -> None:
    """Acceptance check: verify no real API keys, private keys, or live credentials exist."""
    forbidden_patterns = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
        re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    ]
    scan_dirs = [project_root / "src", project_root / "config", project_root / "data"]
    for scan_dir in scan_dirs:
        for path in scan_dir.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".json", ".md", ".yml", ".yaml"}:
                content = path.read_text(encoding="utf-8")
                for pat in forbidden_patterns:
                    assert not pat.search(content), f"Forbidden credential pattern in {path}"
