"""Versioned Pydantic v2 data contracts for the Financial AI Red Teaming Framework."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORTED_SCHEMA_VERSION = "1.0.0"


class ThreatCategory(StrEnum):
    """Canonical financial AI red-teaming threat categories plus benign controls."""

    BENIGN_CONTROL = "benign_control"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SENSITIVE_OUTPUT_LEAKAGE = "sensitive_output_leakage"
    CONFLICTING_INSTRUCTIONS = "conflicting_instructions"
    UNAVAILABLE_APPROVAL = "unavailable_approval"


class Severity(StrEnum):
    """Finding and scenario severity tiers."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(StrEnum):
    """Policy and enforcement gateway decision."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class ScenarioOutcome(StrEnum):
    """High-level outcome for an evaluated scenario."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class ReasonCode(StrEnum):
    """Machine-readable deterministic decision reason codes."""

    POLICY_ALLOWED = "POLICY_ALLOWED"
    POLICY_ROLE_DENIED = "POLICY_ROLE_DENIED"
    POLICY_TOOL_DENIED = "POLICY_TOOL_DENIED"
    POLICY_LIMIT_EXCEEDED = "POLICY_LIMIT_EXCEEDED"
    POLICY_EXPORT_DENIED = "POLICY_EXPORT_DENIED"
    TAINTED_WRITE_DENIED = "TAINTED_WRITE_DENIED"
    CANARY_EGRESS_BLOCKED = "CANARY_EGRESS_BLOCKED"
    CONFLICTING_INSTRUCTIONS_DENIED = "CONFLICTING_INSTRUCTIONS_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_UNAVAILABLE = "APPROVAL_UNAVAILABLE"
    INVALID_TOOL_ARGUMENTS = "INVALID_TOOL_ARGUMENTS"
    MAX_STEPS_EXCEEDED = "MAX_STEPS_EXCEEDED"
    UNGUARDED_EXECUTION = "UNGUARDED_EXECUTION"


class SourceTrust(StrEnum):
    """Provenance trust level of tool outputs and documents."""

    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class AgentMode(StrEnum):
    """Supported execution modes for the simulated target agent."""

    DETERMINISTIC_GUARDED = "deterministic_guarded"
    DETERMINISTIC_UNGUARDED = "deterministic_unguarded"
    OPTIONAL_LLM_STUB = "optional_llm_stub"


class ApprovalServiceStatus(StrEnum):
    """Simulated dual-approval backend availability state."""

    ONLINE = "online"
    UNAVAILABLE = "unavailable"


class CanaryEncoding(StrEnum):
    """Supported canary exfiltration encoding simulations."""

    RAW = "raw"
    BASE64 = "base64"
    SPACED = "spaced"


class MitigationStatus(StrEnum):
    """Regression tracking status for a red-team finding."""

    MITIGATED = "MITIGATED"
    OPEN = "OPEN"
    REGRESSED = "REGRESSED"


class StrictModel(BaseModel):
    """Base model forbidding unexpected fields for strict contract enforcement."""

    model_config = ConfigDict(extra="forbid")


def _validate_schema_version(value: str) -> str:
    if value != SUPPORTED_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported schema_version '{value}'; expected '{SUPPORTED_SCHEMA_VERSION}'."
        )
    return value


class CanarySecret(StrictModel):
    """Synthetic canary secret used strictly for offline leakage detection."""

    canary_id: str = Field(min_length=3)
    label: str = Field(min_length=2)
    value: str = Field(min_length=12)
    classification: str = Field(min_length=3)
    description: str = Field(min_length=5)

    @field_validator("value")
    @classmethod
    def must_be_synthetic_canary(cls, v: str) -> str:
        if not v.startswith("SYNTHETIC_CANARY_"):
            raise ValueError(
                "Canary value must start with 'SYNTHETIC_CANARY_' to prevent real credentials."
            )
        return v


class CanaryRegistry(StrictModel):
    """Collection of synthetic canary fixtures."""

    schema_version: str
    provenance: str
    canaries: list[CanarySecret] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class MockPosition(StrictModel):
    """Synthetic position within a mock account."""

    symbol: str = Field(min_length=2)
    quantity: int = Field(ge=0)
    market_value_usd: float = Field(ge=0.0)


class MockAccount(StrictModel):
    """Synthetic financial account fixture."""

    account_id: str = Field(min_length=4)
    owner_label: str = Field(min_length=3)
    cash_balance_usd: float = Field(ge=0.0)
    risk_tier: str = Field(min_length=2)
    positions: list[MockPosition] = Field(default_factory=list)
    internal_canary_ref: str | None = None

    @field_validator("account_id")
    @classmethod
    def must_be_synthetic_account(cls, v: str) -> str:
        if not v.startswith("ACC-SYNTH-"):
            raise ValueError("Mock account_id must start with 'ACC-SYNTH-'.")
        return v


class MockLedger(StrictModel):
    """Versioned synthetic mock ledger."""

    schema_version: str
    provenance: str
    currency: str = "USD"
    accounts: list[MockAccount] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class AdversarialDocument(StrictModel):
    """Synthetic document fixture (benign or containing indirect prompt injection)."""

    doc_id: str = Field(min_length=4)
    title: str = Field(min_length=3)
    source_trust: SourceTrust
    contains_injection: bool
    content: str = Field(min_length=5)


class DocumentCorpus(StrictModel):
    """Versioned synthetic document corpus."""

    schema_version: str
    provenance: str
    documents: list[AdversarialDocument] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class RolePolicy(StrictModel):
    """Per-role gold policy permissions and thresholds."""

    allowed_tools: list[str]
    max_notional_usd: float = Field(ge=0.0)
    requires_approval_above_usd: float = Field(ge=0.0)
    allow_external_export: bool = False
    allow_secret_access: bool = False


class GoldPolicySet(StrictModel):
    """Deny-by-default gold policy specification."""

    schema_version: str
    policy_set_id: str = Field(min_length=3)
    default_decision: Decision = Decision.DENY
    approved_export_destinations: list[str]
    mutating_tools: list[str]
    read_only_tools: list[str]
    roles: dict[str, RolePolicy]

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)

    @field_validator("default_decision")
    @classmethod
    def enforce_deny_default(cls, v: Decision) -> Decision:
        if v != Decision.DENY:
            raise ValueError("GoldPolicySet default_decision must be DENY (deny-by-default).")
        return v


class EnforcementConfig(StrictModel):
    """Toggleable controls for the enforcement boundary."""

    deny_by_default: bool = True
    enforce_taint_tracking: bool = True
    enforce_canary_egress_filter: bool = True
    enforce_conflict_detection: bool = True
    fail_closed_on_approval_outage: bool = True
    max_tool_steps_per_scenario: int = Field(default=6, ge=1, le=50)


class ApprovalServiceConfig(StrictModel):
    """Simulated approval backend settings."""

    default_status: ApprovalServiceStatus = ApprovalServiceStatus.ONLINE
    valid_tokens: list[str] = Field(default_factory=list)


class ToleranceConfig(StrictModel):
    """Acceptance tolerances for evaluation verification."""

    max_attack_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    max_false_refusal_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    max_canary_leak_count: int = Field(default=0, ge=0)


class FixturePaths(StrictModel):
    """Relative paths to versioned fixture and policy files."""

    gold_policies: str
    canaries: str
    mock_ledger: str
    adversarial_docs: str
    scenarios_suite: str
    reference_oracle: str


class HarnessConfig(StrictModel):
    """Pinned top-level harness configuration."""

    schema_version: str
    config_id: str = Field(min_length=3)
    seed: int = Field(ge=0)
    environment: str = "offline_synthetic_sandbox"
    agent_mode: AgentMode = AgentMode.DETERMINISTIC_GUARDED
    enforcement: EnforcementConfig = Field(default_factory=EnforcementConfig)
    approval_service: ApprovalServiceConfig = Field(default_factory=ApprovalServiceConfig)
    tolerances: ToleranceConfig = Field(default_factory=ToleranceConfig)
    fixtures: FixturePaths

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class ToolCallRequest(StrictModel):
    """A proposed tool invocation submitted to the enforcement gateway."""

    tool_name: str = Field(min_length=2)
    arguments: dict[str, Any] = Field(default_factory=dict)
    origin: str = "user_plan"

    @model_validator(mode="after")
    def validate_amount_boundaries(self) -> ToolCallRequest:
        if "amount_usd" in self.arguments:
            amt = self.arguments["amount_usd"]
            if not isinstance(amt, (int, float)) or amt <= 0:
                raise ValueError("Tool argument 'amount_usd' must be a positive number.")
        return self


class CanaryAttemptSpec(StrictModel):
    """Optional simulated canary exfiltration payload for red-team testing."""

    canary_id: str
    encoding: CanaryEncoding = CanaryEncoding.RAW


class Scenario(StrictModel):
    """Single red-teaming or benign control test scenario."""

    scenario_id: str = Field(min_length=3)
    title: str = Field(min_length=3)
    category: ThreatCategory
    severity: Severity
    is_adversarial: bool
    actor_role: str = Field(min_length=2)
    account_id: str = Field(min_length=4)
    user_prompt: str = Field(min_length=3)
    expected_outcome: ScenarioOutcome
    expected_reason_code: ReasonCode
    mitigation_id: str = Field(min_length=3)
    proposed_plan: list[ToolCallRequest] = Field(default_factory=list)
    approval_service_override: ApprovalServiceStatus | None = None
    inject_canary_attempt: CanaryAttemptSpec | None = None


class ScenarioSuite(StrictModel):
    """Versioned collection of evaluation scenarios."""

    schema_version: str
    suite_id: str = Field(min_length=3)
    description: str
    scenarios: list[Scenario] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class OracleExpectedSummary(StrictModel):
    """Hand-calculated expected aggregate summary for the reference oracle."""

    total_scenarios: int = Field(ge=1)
    adversarial_scenarios: int = Field(ge=0)
    benign_scenarios: int = Field(ge=0)
    attack_success_count: int = Field(ge=0)
    attack_success_rate: float = Field(ge=0.0, le=1.0)
    false_refusal_count: int = Field(ge=0)
    false_refusal_rate: float = Field(ge=0.0, le=1.0)
    canary_leak_count: int = Field(ge=0)


class ReferenceOracle(StrictModel):
    """Deterministic hand-calculated reference fixture for sanity & baseline checks."""

    schema_version: str
    oracle_id: str
    description: str
    expected_summary: OracleExpectedSummary
    scenarios: list[Scenario] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        return _validate_schema_version(v)


class PolicyDecision(StrictModel):
    """Pure domain output of the Identity & Policy boundary."""

    decision: Decision
    reason_code: ReasonCode
    detail: str
    policy_rule: str


class ToolCallResult(StrictModel):
    """Outcome of a single tool call passing through the Enforcement Gateway."""

    step_index: int = Field(ge=1)
    tool_name: str
    origin: str
    decision: Decision
    reason_code: ReasonCode
    detail: str
    tainted_context: bool
    source_trust: SourceTrust | None = None
    output_summary: str
    canary_ids_detected: list[str] = Field(default_factory=list)


class AuditEvent(StrictModel):
    """Structured redacted audit log event."""

    event_id: str
    run_id: str
    scenario_id: str
    sequence: int = Field(ge=1)
    timestamp_utc: str
    boundary: str
    event_type: str
    actor_role: str
    decision: Decision | None = None
    reason_code: ReasonCode | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ScenarioVerdict(StrictModel):
    """Structured evaluation verdict for a single scenario."""

    scenario_id: str
    title: str
    category: ThreatCategory
    severity: Severity
    is_adversarial: bool
    actor_role: str
    expected_outcome: ScenarioOutcome
    actual_outcome: ScenarioOutcome
    expected_reason_code: ReasonCode
    actual_reason_codes: list[ReasonCode]
    mitigation_id: str
    passed: bool
    attack_succeeded: bool
    false_refusal: bool
    canary_leaked: bool
    leaked_canary_ids: list[str] = Field(default_factory=list)
    tool_trace: list[ToolCallResult] = Field(default_factory=list)
    final_response_redacted: str
    audit_event_ids: list[str] = Field(default_factory=list)


class CategoryMetrics(StrictModel):
    """Aggregated attack success and false refusal rates for a category."""

    category: ThreatCategory
    total: int = Field(ge=0)
    adversarial_total: int = Field(ge=0)
    benign_total: int = Field(ge=0)
    attack_success_count: int = Field(ge=0)
    attack_success_rate: float | None = None
    false_refusal_count: int = Field(ge=0)
    false_refusal_rate: float | None = None
    canary_leak_count: int = Field(ge=0)


class SummaryMetrics(StrictModel):
    """Top-level evaluation summary metrics."""

    total_scenarios: int
    adversarial_scenarios: int
    benign_scenarios: int
    passed_scenarios: int
    failed_scenarios: int
    attack_success_count: int
    attack_success_rate: float
    false_refusal_count: int
    false_refusal_rate: float
    canary_leak_count: int
    within_tolerances: bool


class RuntimeMetadata(StrictModel):
    """Recorded runtime provenance for reproducible evaluation outputs."""

    framework_version: str
    python_version: str
    platform: str
    config_sha256: str
    suite_sha256: str
    policy_sha256: str
    seed: int
    recorded_at_utc: str


class EvaluationReport(StrictModel):
    """Versioned machine-readable output contract for an evaluation run."""

    schema_version: str = SUPPORTED_SCHEMA_VERSION
    run_id: str
    config_id: str
    suite_id: str
    agent_mode: AgentMode
    runtime_metadata: RuntimeMetadata
    summary: SummaryMetrics
    category_metrics: dict[str, CategoryMetrics]
    diagnostic_counters: dict[str, int]
    verdicts: list[ScenarioVerdict]
    audit_events: list[AuditEvent]


class RegressionFinding(StrictModel):
    """Actionable red-team finding with severity, reproduction, and mitigation tracking."""

    finding_id: str
    scenario_id: str
    category: ThreatCategory
    severity: Severity
    title: str
    status: MitigationStatus
    mitigation_id: str
    mitigation_description: str
    reproduction_command: str
    unguarded_attack_succeeded: bool
    guarded_attack_blocked: bool
    guarded_reason_codes: list[ReasonCode]
    baseline_regression: bool = False


class RegressionReport(StrictModel):
    """Versioned regression and mitigation tracking report."""

    schema_version: str = SUPPORTED_SCHEMA_VERSION
    report_id: str
    generated_at_utc: str
    guarded_run_id: str
    unguarded_run_id: str | None = None
    baseline_run_id: str | None = None
    overall_status: str
    regressions_detected: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    mitigated_findings: int = Field(ge=0)
    guarded_asr: float
    guarded_frr: float
    unguarded_asr: float | None = None
    unguarded_frr: float | None = None
    metric_deltas_vs_baseline: dict[str, float] = Field(default_factory=dict)
    findings: list[RegressionFinding] = Field(default_factory=list)
