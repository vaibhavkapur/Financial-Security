"""Regression reporting, baseline comparison, and mitigation tracking."""

from __future__ import annotations

from datetime import UTC, datetime

from fin_redteam.models import (
    EvaluationReport,
    MitigationStatus,
    RegressionFinding,
    RegressionReport,
)

MITIGATION_CATALOG: dict[str, str] = {
    "MIT-BASELINE-ALLOW": "Permits verified, policy-compliant read/write financial workflows without false refusal.",
    "MIT-TAINT-GATE": "Provenance taint tracking blocks mutating tool invocations after reading untrusted external content.",
    "MIT-RBAC-DENY-DEFAULT": "Deny-by-default role allowlist rejects unauthorized or privilege-escalating tool calls.",
    "MIT-NOTIONAL-CAP": "Per-role notional USD cap blocks orders or transfers exceeding authorized limits.",
    "MIT-CANARY-EGRESS": "Canary egress filter inspects tool arguments and assistant responses for raw, base64, and obfuscated secrets.",
    "MIT-CONFLICT-HALT": "Conflict detector halts execution fail-closed when contradictory authority directives appear.",
    "MIT-FAIL-CLOSED-APPROVAL": "Dual-approval gate fails closed when the approval verification service is unavailable.",
    "MIT-SCHEMA-VALIDATION": "Strict Pydantic v2 contract validation rejects malformed payloads and invalid bounds.",
}


def compare_against_baseline(
    candidate: EvaluationReport,
    baseline: EvaluationReport,
) -> list[str]:
    """Compare candidate evaluation results against a pinned baseline report."""
    discrepancies: list[str] = []
    if candidate.suite_id != baseline.suite_id:
        discrepancies.append(
            f"Suite mismatch: baseline='{baseline.suite_id}', candidate='{candidate.suite_id}'."
        )
    if candidate.summary.attack_success_rate > baseline.summary.attack_success_rate:
        discrepancies.append(
            f"ASR regression: baseline={baseline.summary.attack_success_rate:.4f}, "
            f"candidate={candidate.summary.attack_success_rate:.4f}."
        )
    if candidate.summary.false_refusal_rate > baseline.summary.false_refusal_rate:
        discrepancies.append(
            f"FRR regression: baseline={baseline.summary.false_refusal_rate:.4f}, "
            f"candidate={candidate.summary.false_refusal_rate:.4f}."
        )
    if candidate.summary.canary_leak_count > baseline.summary.canary_leak_count:
        discrepancies.append(
            f"Canary leak regression: baseline={baseline.summary.canary_leak_count}, "
            f"candidate={candidate.summary.canary_leak_count}."
        )

    baseline_by_id = {v.scenario_id: v for v in baseline.verdicts}
    for cand_v in candidate.verdicts:
        base_v = baseline_by_id.get(cand_v.scenario_id)
        if base_v is None:
            continue
        if base_v.passed and not cand_v.passed:
            discrepancies.append(
                f"Scenario {cand_v.scenario_id} regressed from PASS to FAIL "
                f"(actual={cand_v.actual_outcome.value}, reasons={[r.value for r in cand_v.actual_reason_codes]})."
            )
        elif base_v.actual_outcome != cand_v.actual_outcome:
            discrepancies.append(
                f"Scenario {cand_v.scenario_id} outcome changed: "
                f"{base_v.actual_outcome.value} -> {cand_v.actual_outcome.value}."
            )
        elif base_v.actual_reason_codes != cand_v.actual_reason_codes:
            discrepancies.append(
                f"Scenario {cand_v.scenario_id} reason codes changed: "
                f"{[r.value for r in base_v.actual_reason_codes]} -> "
                f"{[r.value for r in cand_v.actual_reason_codes]}."
            )

    return discrepancies


def build_regression_report(
    *,
    guarded_report: EvaluationReport,
    unguarded_report: EvaluationReport | None = None,
    baseline_report: EvaluationReport | None = None,
    config_rel_path: str = "config/harness_config.json",
    fixed_timestamp_utc: str | None = None,
) -> RegressionReport:
    """Build a structured regression report with severity, reproduction, and mitigation tracking."""
    unguarded_by_id = (
        {v.scenario_id: v for v in unguarded_report.verdicts} if unguarded_report else {}
    )
    baseline_by_id = {v.scenario_id: v for v in baseline_report.verdicts} if baseline_report else {}

    findings: list[RegressionFinding] = []
    regressions_detected = 0
    open_findings = 0
    mitigated_findings = 0

    for idx, verdict in enumerate(guarded_report.verdicts, start=1):
        if not verdict.is_adversarial and verdict.passed:
            # Benign passing controls do not create vulnerability findings.
            continue

        ung = unguarded_by_id.get(verdict.scenario_id)
        base = baseline_by_id.get(verdict.scenario_id)
        unguarded_succeeded = bool(ung.attack_succeeded) if ung else False
        baseline_regressed = bool(base is not None and base.passed and not verdict.passed)

        if baseline_regressed:
            status = MitigationStatus.REGRESSED
            regressions_detected += 1
        elif not verdict.passed:
            status = MitigationStatus.OPEN
            open_findings += 1
        else:
            status = MitigationStatus.MITIGATED
            mitigated_findings += 1

        repro_mode = "deterministic_unguarded" if unguarded_succeeded else "deterministic_guarded"
        repro_cmd = (
            f"uv run fin-redteam run-scenario --config {config_rel_path} "
            f"--scenario-id {verdict.scenario_id} --mode {repro_mode}"
        )

        findings.append(
            RegressionFinding(
                finding_id=f"FIND-{idx:03d}-{verdict.scenario_id}",
                scenario_id=verdict.scenario_id,
                category=verdict.category,
                severity=verdict.severity,
                title=verdict.title,
                status=status,
                mitigation_id=verdict.mitigation_id,
                mitigation_description=MITIGATION_CATALOG.get(
                    verdict.mitigation_id, "Documented policy/enforcement control."
                ),
                reproduction_command=repro_cmd,
                unguarded_attack_succeeded=unguarded_succeeded,
                guarded_attack_blocked=(not verdict.attack_succeeded) if verdict.is_adversarial else False,
                guarded_reason_codes=verdict.actual_reason_codes,
                baseline_regression=baseline_regressed,
            )
        )

    metric_deltas: dict[str, float] = {}
    if baseline_report is not None:
        metric_deltas = {
            "attack_success_rate_delta": round(
                guarded_report.summary.attack_success_rate
                - baseline_report.summary.attack_success_rate,
                6,
            ),
            "false_refusal_rate_delta": round(
                guarded_report.summary.false_refusal_rate
                - baseline_report.summary.false_refusal_rate,
                6,
            ),
            "canary_leak_count_delta": float(
                guarded_report.summary.canary_leak_count - baseline_report.summary.canary_leak_count
            ),
        }

    overall_status = (
        "PASS"
        if regressions_detected == 0
        and open_findings == 0
        and guarded_report.summary.within_tolerances
        else "FAIL"
    )

    generated_at = (
        fixed_timestamp_utc
        if fixed_timestamp_utc is not None
        else datetime.now(UTC).isoformat()
    )

    return RegressionReport(
        report_id=f"REG-{guarded_report.run_id}",
        generated_at_utc=generated_at,
        guarded_run_id=guarded_report.run_id,
        unguarded_run_id=unguarded_report.run_id if unguarded_report else None,
        baseline_run_id=baseline_report.run_id if baseline_report else None,
        overall_status=overall_status,
        regressions_detected=regressions_detected,
        open_findings=open_findings,
        mitigated_findings=mitigated_findings,
        guarded_asr=guarded_report.summary.attack_success_rate,
        guarded_frr=guarded_report.summary.false_refusal_rate,
        unguarded_asr=unguarded_report.summary.attack_success_rate if unguarded_report else None,
        unguarded_frr=unguarded_report.summary.false_refusal_rate if unguarded_report else None,
        metric_deltas_vs_baseline=metric_deltas,
        findings=findings,
    )


def render_regression_markdown(
    reg_report: RegressionReport,
    guarded_report: EvaluationReport,
) -> str:
    """Render a human-readable Markdown regression report with severity, reproduction, and mitigation tracking."""
    lines: list[str] = [
        "# Financial AI Red-Teaming Regression Report",
        "",
        f"- **Report ID:** `{reg_report.report_id}`",
        f"- **Overall Status:** `{reg_report.overall_status}`",
        f"- **Guarded Run ID:** `{reg_report.guarded_run_id}`",
        f"- **Unguarded Reference Run ID:** `{reg_report.unguarded_run_id or 'N/A'}`",
        f"- **Baseline Run ID:** `{reg_report.baseline_run_id or 'N/A'}`",
        f"- **Generated At (UTC):** `{reg_report.generated_at_utc}`",
        "",
        "## 1. Executive Metric Summary (Measured Synthetic Fixture Run)",
        "",
        "| Metric | Unguarded Reference | Guarded Harness | Baseline Delta |",
        "|---|---:|---:|---:|",
        f"| Attack Success Rate (ASR) | {f'{reg_report.unguarded_asr:.1%}' if reg_report.unguarded_asr is not None else 'N/A'} | {reg_report.guarded_asr:.1%} | {reg_report.metric_deltas_vs_baseline.get('attack_success_rate_delta', 0.0):+.4f} |",
        f"| False Refusal Rate (FRR) | {f'{reg_report.unguarded_frr:.1%}' if reg_report.unguarded_frr is not None else 'N/A'} | {reg_report.guarded_frr:.1%} | {reg_report.metric_deltas_vs_baseline.get('false_refusal_rate_delta', 0.0):+.4f} |",
        f"| Canary Leaks | N/A | {guarded_report.summary.canary_leak_count} | {reg_report.metric_deltas_vs_baseline.get('canary_leak_count_delta', 0.0):+.0f} |",
        f"| Mitigated Findings | - | {reg_report.mitigated_findings} | - |",
        f"| Open / Regressed Findings | - | {reg_report.open_findings} / {reg_report.regressions_detected} | - |",
        "",
        "## 2. Attack Success Rate (ASR) and False Refusal Rate (FRR) by Category",
        "",
        "| Category | Total | Adversarial | Benign | Attack Successes | ASR | False Refusals | FRR | Canary Leaks |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for cat_key, cm in guarded_report.category_metrics.items():
        asr_str = f"{cm.attack_success_rate:.1%}" if cm.attack_success_rate is not None else "N/A"
        frr_str = f"{cm.false_refusal_rate:.1%}" if cm.false_refusal_rate is not None else "N/A"
        lines.append(
            f"| `{cat_key}` | {cm.total} | {cm.adversarial_total} | {cm.benign_total} "
            f"| {cm.attack_success_count} | {asr_str} | {cm.false_refusal_count} | {frr_str} "
            f"| {cm.canary_leak_count} |"
        )

    lines.extend(
        [
            "",
            "## 3. Finding, Severity, Reproduction & Mitigation Tracking",
            "",
            "| Finding ID | Scenario | Category | Severity | Status | Unguarded Exploited | Guarded Reason Code(s) | Mitigation ID |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )

    for f in reg_report.findings:
        codes = ", ".join(f"`{r.value}`" for r in f.guarded_reason_codes)
        lines.append(
            f"| `{f.finding_id}` | `{f.scenario_id}` | `{f.category.value}` | **{f.severity.value}** "
            f"| `{f.status.value}` | `{f.unguarded_attack_succeeded}` | {codes} | `{f.mitigation_id}` |"
        )

    lines.extend(["", "## 4. Reproduction Commands & Mitigation Details", ""])
    for f in reg_report.findings:
        lines.extend(
            [
                f"### `{f.finding_id}` — {f.title}",
                f"- **Severity:** {f.severity.value} | **Status:** `{f.status.value}` | **Mitigation:** `{f.mitigation_id}`",
                f"- **Mitigation Control:** {f.mitigation_description}",
                f"- **Reproduce:** `{f.reproduction_command}`",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"
