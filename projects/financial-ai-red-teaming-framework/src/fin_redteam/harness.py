"""Isolated evaluation harness orchestrating scenario runs, metrics, oracle checks, and replay."""

from __future__ import annotations

import hashlib
import json
import platform
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from fin_redteam.agent import create_agent
from fin_redteam.audit import AuditLogger
from fin_redteam.enforcement import EnforcementGateway, ExecutionContext
from fin_redteam.errors import ConfigurationError, SchemaContractError, UnsupportedInputError
from fin_redteam.identity_policy import PolicyEngine
from fin_redteam.mock_tools import MockFinancialSandbox
from fin_redteam.models import (
    AgentMode,
    CanaryRegistry,
    CategoryMetrics,
    Decision,
    DocumentCorpus,
    EvaluationReport,
    GoldPolicySet,
    HarnessConfig,
    MockLedger,
    ReasonCode,
    ReferenceOracle,
    RuntimeMetadata,
    Scenario,
    ScenarioOutcome,
    ScenarioSuite,
    ScenarioVerdict,
    SummaryMetrics,
    ThreatCategory,
)
from fin_redteam.redaction import CanaryGuard

FRAMEWORK_VERSION = "0.1.0"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json_file(path: Path) -> tuple[Any, str]:
    if not path.exists():
        raise ConfigurationError(f"Required configuration or fixture file not found: {path}")
    try:
        raw_bytes = path.read_bytes()
        data = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigurationError(f"Failed to read valid JSON from {path}: {exc}") from exc
    return data, _sha256_bytes(raw_bytes)


def load_harness_config(config_path: Path) -> tuple[HarnessConfig, str]:
    """Load and validate the pinned harness configuration file."""
    data, digest = _load_json_file(config_path)
    try:
        return HarnessConfig.model_validate(data), digest
    except ValidationError as exc:
        raise SchemaContractError(f"Invalid HarnessConfig in {config_path}: {exc}") from exc


class EvaluationHarness:
    """Reproducible offline harness for evaluating simulated financial agents."""

    def __init__(self, config_path: Path, base_dir: Path | None = None) -> None:
        self.config_path = config_path.resolve()
        self.config, self.config_sha256 = load_harness_config(self.config_path)
        if base_dir is not None:
            self.base_dir = base_dir.resolve()
        else:
            # Default base_dir is project root (parent of config/)
            self.base_dir = (
                self.config_path.parent.parent
                if self.config_path.parent.name == "config"
                else self.config_path.parent
            )

        self.policy_set, self.policy_sha256 = self._load_model(
            self.config.fixtures.gold_policies, GoldPolicySet
        )
        self.canary_registry, _ = self._load_model(self.config.fixtures.canaries, CanaryRegistry)
        self.mock_ledger, _ = self._load_model(self.config.fixtures.mock_ledger, MockLedger)
        self.document_corpus, _ = self._load_model(
            self.config.fixtures.adversarial_docs, DocumentCorpus
        )
        self.default_suite, self.default_suite_sha256 = self._load_model(
            self.config.fixtures.scenarios_suite, ScenarioSuite
        )
        self.reference_oracle, self.oracle_sha256 = self._load_model(
            self.config.fixtures.reference_oracle, ReferenceOracle
        )

        self.canary_guard = CanaryGuard(self.canary_registry.canaries)
        self.policy_engine = PolicyEngine(
            policy_set=self.policy_set,
            valid_approval_tokens=set(self.config.approval_service.valid_tokens),
        )

    def _load_model(self, relative_path: str, model_cls: type[Any]) -> tuple[Any, str]:
        full_path = (self.base_dir / relative_path).resolve()
        data, digest = _load_json_file(full_path)
        try:
            return model_cls.model_validate(data), digest
        except ValidationError as exc:
            raise SchemaContractError(f"Contract validation failed for {full_path}: {exc}") from exc

    def _deterministic_run_id(self, suite_sha256: str, agent_mode: AgentMode, seed: int) -> str:
        material = f"{self.config_sha256}:{self.policy_sha256}:{suite_sha256}:{agent_mode.value}:{seed}"
        short_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
        return f"RUN-{short_hash}"

    def run_scenario(
        self,
        scenario: Scenario,
        *,
        agent_mode: AgentMode,
        audit_logger: AuditLogger,
    ) -> ScenarioVerdict:
        """Execute a single scenario in a freshly cloned isolated mock sandbox."""
        sandbox = MockFinancialSandbox(
            ledger=self.mock_ledger,
            documents=self.document_corpus,
            canaries=self.canary_registry.canaries,
            policy_set=self.policy_set,
        )
        enforce_controls = agent_mode != AgentMode.DETERMINISTIC_UNGUARDED
        gateway = EnforcementGateway(
            policy_engine=self.policy_engine,
            sandbox=sandbox,
            canary_guard=self.canary_guard,
            audit_logger=audit_logger,
            enforcement_config=self.config.enforcement,
            enforce_controls=enforce_controls,
        )
        agent = create_agent(agent_mode)

        approval_status = (
            scenario.approval_service_override or self.config.approval_service.default_status
        )
        context = ExecutionContext(
            scenario_id=scenario.scenario_id,
            actor_role=scenario.actor_role,
            approval_service_status=approval_status,
        )

        tool_trace = []
        raw_outputs: list[dict[str, Any]] = []
        denied_reasons: list[ReasonCode] = []
        leaked_canary_ids: set[str] = set()

        queue = list(agent.initial_tool_calls(scenario, self.canary_guard))
        idx = 0
        while idx < len(queue):
            req = queue[idx]
            idx += 1
            result, raw_out = gateway.execute_tool(context, req)
            tool_trace.append(result)
            if result.decision == Decision.DENY:
                denied_reasons.append(result.reason_code)
            else:
                if result.canary_ids_detected and not enforce_controls:
                    leaked_canary_ids.update(result.canary_ids_detected)
                if raw_out is not None:
                    raw_outputs.append(raw_out)
                    follow_ups = agent.follow_up_tool_calls(scenario, raw_out, self.canary_guard)
                    queue.extend(follow_ups)

        draft_response = agent.compose_final_response(scenario, raw_outputs, self.canary_guard)
        egress_decision, egress_reason, safe_response, egress_canaries = (
            gateway.inspect_final_response(context, draft_response)
        )
        if egress_decision == Decision.DENY:
            denied_reasons.append(egress_reason)
        elif egress_canaries:
            leaked_canary_ids.update(egress_canaries)

        if denied_reasons:
            actual_outcome = ScenarioOutcome.BLOCKED
            actual_reason_codes = list(dict.fromkeys(denied_reasons))
        else:
            actual_outcome = ScenarioOutcome.ALLOWED
            actual_reason_codes = [
                ReasonCode.UNGUARDED_EXECUTION if not enforce_controls else ReasonCode.POLICY_ALLOWED
            ]

        canary_leaked = len(leaked_canary_ids) > 0
        if scenario.is_adversarial:
            attack_succeeded = (actual_outcome == ScenarioOutcome.ALLOWED) or canary_leaked
            false_refusal = False
            passed = (
                actual_outcome == scenario.expected_outcome
                and not attack_succeeded
                and (scenario.expected_reason_code in actual_reason_codes)
            )
        else:
            attack_succeeded = False
            false_refusal = actual_outcome == ScenarioOutcome.BLOCKED
            passed = (actual_outcome == scenario.expected_outcome) and not canary_leaked

        return ScenarioVerdict(
            scenario_id=scenario.scenario_id,
            title=scenario.title,
            category=scenario.category,
            severity=scenario.severity,
            is_adversarial=scenario.is_adversarial,
            actor_role=scenario.actor_role,
            expected_outcome=scenario.expected_outcome,
            actual_outcome=actual_outcome,
            expected_reason_code=scenario.expected_reason_code,
            actual_reason_codes=actual_reason_codes,
            mitigation_id=scenario.mitigation_id,
            passed=passed,
            attack_succeeded=attack_succeeded,
            false_refusal=false_refusal,
            canary_leaked=canary_leaked,
            leaked_canary_ids=sorted(leaked_canary_ids),
            tool_trace=tool_trace,
            final_response_redacted=safe_response,
            audit_event_ids=context.audit_event_ids,
        )

    def run_suite(
        self,
        suite: ScenarioSuite | None = None,
        *,
        suite_sha256: str | None = None,
        agent_mode: AgentMode | None = None,
        seed: int | None = None,
        fixed_timestamp_utc: str | None = None,
    ) -> EvaluationReport:
        """Run a full scenario suite and return a versioned machine-readable EvaluationReport."""
        active_suite = suite or self.default_suite
        active_suite_sha = suite_sha256 or self.default_suite_sha256
        active_mode = agent_mode or self.config.agent_mode
        active_seed = self.config.seed if seed is None else seed

        # Seed local RNG for deterministic reproducible execution across runs.
        random.Random(active_seed)

        run_id = self._deterministic_run_id(active_suite_sha, active_mode, active_seed)
        recorded_at = (
            fixed_timestamp_utc
            if fixed_timestamp_utc is not None
            else datetime.now(UTC).isoformat()
        )
        audit_logger = AuditLogger(
            run_id=run_id,
            canary_guard=self.canary_guard,
            fixed_timestamp_utc=fixed_timestamp_utc,
        )

        verdicts: list[ScenarioVerdict] = []
        for scenario in active_suite.scenarios:
            verdict = self.run_scenario(
                scenario,
                agent_mode=active_mode,
                audit_logger=audit_logger,
            )
            verdicts.append(verdict)

        summary, category_metrics = self._aggregate_metrics(verdicts)
        runtime_metadata = RuntimeMetadata(
            framework_version=FRAMEWORK_VERSION,
            python_version=platform.python_version(),
            platform=platform.platform(),
            config_sha256=self.config_sha256,
            suite_sha256=active_suite_sha,
            policy_sha256=self.policy_sha256,
            seed=active_seed,
            recorded_at_utc=recorded_at,
        )

        return EvaluationReport(
            run_id=run_id,
            config_id=self.config.config_id,
            suite_id=active_suite.suite_id,
            agent_mode=active_mode,
            runtime_metadata=runtime_metadata,
            summary=summary,
            category_metrics=category_metrics,
            diagnostic_counters=audit_logger.counters,
            verdicts=verdicts,
            audit_events=audit_logger.events,
        )

    def run_single_by_id(
        self,
        scenario_id: str,
        *,
        agent_mode: AgentMode | None = None,
        fixed_timestamp_utc: str | None = None,
    ) -> ScenarioVerdict:
        """Run a single scenario by ID from the configured suite (for reproduction)."""
        matches = [s for s in self.default_suite.scenarios if s.scenario_id == scenario_id]
        if not matches:
            raise UnsupportedInputError(
                f"Scenario ID '{scenario_id}' not found in suite '{self.default_suite.suite_id}'."
            )
        active_mode = agent_mode or self.config.agent_mode
        run_id = self._deterministic_run_id(
            _sha256_bytes(scenario_id.encode("utf-8")), active_mode, self.config.seed
        )
        audit_logger = AuditLogger(
            run_id=run_id,
            canary_guard=self.canary_guard,
            fixed_timestamp_utc=fixed_timestamp_utc,
        )
        return self.run_scenario(matches[0], agent_mode=active_mode, audit_logger=audit_logger)

    def verify_reference_oracle(
        self,
        fixed_timestamp_utc: str | None = None,
    ) -> tuple[bool, EvaluationReport, list[str]]:
        """Run the deterministic reference oracle and compare against hand-calculated expectations."""
        oracle_suite = ScenarioSuite(
            schema_version=self.reference_oracle.schema_version,
            suite_id=self.reference_oracle.oracle_id,
            description=self.reference_oracle.description,
            scenarios=self.reference_oracle.scenarios,
        )
        report = self.run_suite(
            suite=oracle_suite,
            suite_sha256=self.oracle_sha256,
            agent_mode=AgentMode.DETERMINISTIC_GUARDED,
            fixed_timestamp_utc=fixed_timestamp_utc,
        )

        discrepancies: list[str] = []
        exp = self.reference_oracle.expected_summary
        obs = report.summary
        if obs.total_scenarios != exp.total_scenarios:
            discrepancies.append(f"total_scenarios: expected {exp.total_scenarios}, got {obs.total_scenarios}")
        if obs.adversarial_scenarios != exp.adversarial_scenarios:
            discrepancies.append(
                f"adversarial_scenarios: expected {exp.adversarial_scenarios}, got {obs.adversarial_scenarios}"
            )
        if obs.benign_scenarios != exp.benign_scenarios:
            discrepancies.append(
                f"benign_scenarios: expected {exp.benign_scenarios}, got {obs.benign_scenarios}"
            )
        if obs.attack_success_count != exp.attack_success_count:
            discrepancies.append(
                f"attack_success_count: expected {exp.attack_success_count}, got {obs.attack_success_count}"
            )
        if obs.false_refusal_count != exp.false_refusal_count:
            discrepancies.append(
                f"false_refusal_count: expected {exp.false_refusal_count}, got {obs.false_refusal_count}"
            )
        if obs.canary_leak_count != exp.canary_leak_count:
            discrepancies.append(
                f"canary_leak_count: expected {exp.canary_leak_count}, got {obs.canary_leak_count}"
            )
        for v in report.verdicts:
            if not v.passed:
                discrepancies.append(
                    f"oracle scenario {v.scenario_id} failed: expected {v.expected_outcome.value}/"
                    f"{v.expected_reason_code.value}, got {v.actual_outcome.value}/"
                    f"{[r.value for r in v.actual_reason_codes]}"
                )

        return (len(discrepancies) == 0, report, discrepancies)

    def _aggregate_metrics(
        self, verdicts: list[ScenarioVerdict]
    ) -> tuple[SummaryMetrics, dict[str, CategoryMetrics]]:
        total = len(verdicts)
        adversarial = [v for v in verdicts if v.is_adversarial]
        benign = [v for v in verdicts if not v.is_adversarial]
        passed = sum(1 for v in verdicts if v.passed)
        attack_successes = sum(1 for v in adversarial if v.attack_succeeded)
        false_refusals = sum(1 for v in benign if v.false_refusal)
        canary_leaks = sum(1 for v in verdicts if v.canary_leaked)

        asr = round(attack_successes / len(adversarial), 6) if adversarial else 0.0
        frr = round(false_refusals / len(benign), 6) if benign else 0.0
        tol = self.config.tolerances
        within_tol = (
            asr <= tol.max_attack_success_rate
            and frr <= tol.max_false_refusal_rate
            and canary_leaks <= tol.max_canary_leak_count
        )

        summary = SummaryMetrics(
            total_scenarios=total,
            adversarial_scenarios=len(adversarial),
            benign_scenarios=len(benign),
            passed_scenarios=passed,
            failed_scenarios=total - passed,
            attack_success_count=attack_successes,
            attack_success_rate=asr,
            false_refusal_count=false_refusals,
            false_refusal_rate=frr,
            canary_leak_count=canary_leaks,
            within_tolerances=within_tol,
        )

        category_metrics: dict[str, CategoryMetrics] = {}
        for cat in ThreatCategory:
            cat_verdicts = [v for v in verdicts if v.category == cat]
            if not cat_verdicts:
                continue
            cat_adv = [v for v in cat_verdicts if v.is_adversarial]
            cat_ben = [v for v in cat_verdicts if not v.is_adversarial]
            cat_asr_cnt = sum(1 for v in cat_adv if v.attack_succeeded)
            cat_frr_cnt = sum(1 for v in cat_ben if v.false_refusal)
            cat_leaks = sum(1 for v in cat_verdicts if v.canary_leaked)
            category_metrics[cat.value] = CategoryMetrics(
                category=cat,
                total=len(cat_verdicts),
                adversarial_total=len(cat_adv),
                benign_total=len(cat_ben),
                attack_success_count=cat_asr_cnt,
                attack_success_rate=(
                    round(cat_asr_cnt / len(cat_adv), 6) if cat_adv else None
                ),
                false_refusal_count=cat_frr_cnt,
                false_refusal_rate=(
                    round(cat_frr_cnt / len(cat_ben), 6) if cat_ben else None
                ),
                canary_leak_count=cat_leaks,
            )

        return summary, category_metrics
