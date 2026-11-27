# Data Contracts — Financial AI Red Teaming Framework

All configuration, fixture, and report schemas are defined as strict Pydantic v2 models (`extra="forbid"`) in `src/fin_redteam/models.py` and versioned with `schema_version = "1.0.0"`.

## 1. Versioning, Units, Timestamps, and Identifiers

| Dimension | Convention | Enforcement |
|---|---|---|
| **Schema Version** | SemVer string (`"1.0.0"`) | Exact match validated by `_validate_schema_version`; mismatches raise `SchemaContractError`. |
| **Monetary Units** | `USD` floating-point amounts (`amount_usd`, `cash_balance_usd`, `max_notional_usd`, `requires_approval_above_usd`) | Balances/limits must be `>= 0.0`; tool invocation `amount_usd` must be strictly `> 0.0`. |
| **Timestamps** | ISO-8601 UTC strings (`timestamp_utc`, `recorded_at_utc`, `generated_at_utc`) | Defaults to `datetime.now(timezone.utc).isoformat()`; supports deterministic `fixed_timestamp_utc` injection for replay tests. |
| **Run Identifiers** | `RUN-<12-hex-sha256>` | Deterministic hash of `(config_sha256, policy_sha256, suite_sha256, agent_mode, seed)`. |
| **Event Identifiers** | `EVT-<run_id>-<4-digit-seq>` | Monotonic deterministic sequence per run. |
| **Scenario / Canary / Account IDs** | `SCN-*` / `ORACLE-*`, `CANARY-*`, `ACC-SYNTH-*` | Account IDs must start with `ACC-SYNTH-`; canary secret values must start with `SYNTHETIC_CANARY_`. |

## 2. Canonical Input Schemas

### 2.1 `HarnessConfig` (`config/harness_config.json`)
- `schema_version`: `"1.0.0"`
- `config_id`: Non-empty identifier (`"default-redteam-v1"`)
- `seed`: Non-negative integer (`20261127`)
- `agent_mode`: `deterministic_guarded | deterministic_unguarded | optional_llm_stub`
- `enforcement`: Booleans for `deny_by_default`, `enforce_taint_tracking`, `enforce_canary_egress_filter`, `enforce_conflict_detection`, `fail_closed_on_approval_outage`, plus `max_tool_steps_per_scenario` (`1..50`).
- `approval_service`: `default_status` (`online | unavailable`) and `valid_tokens`.
- `tolerances`: `max_attack_success_rate` (`0.0..1.0`), `max_false_refusal_rate` (`0.0..1.0`), `max_canary_leak_count` (`>= 0`).
- `fixtures`: Relative paths to `gold_policies`, `canaries`, `mock_ledger`, `adversarial_docs`, `scenarios_suite`, and `reference_oracle`.

### 2.2 `GoldPolicySet` (`config/gold_policies.json`)
- `default_decision`: Must be `"DENY"`.
- `approved_export_destinations`: Allowlist of internal URI targets (e.g., `internal://compliance-vault`).
- `mutating_tools` / `read_only_tools`: Tool classification sets for provenance taint enforcement.
- `roles`: Map of `role_name -> RolePolicy(allowed_tools, max_notional_usd, requires_approval_above_usd, allow_external_export, allow_secret_access)`.

### 2.3 Synthetic Fixtures (`data/fixtures/`)
- `CanaryRegistry` (`canaries.json`): Provenance `"synthetic_offline_fixture"`, list of `CanarySecret`.
- `MockLedger` (`mock_ledger.json`): Synthetic accounts (`ACC-SYNTH-*`) and positions.
- `DocumentCorpus` (`adversarial_docs.json`): Documents labeled with `source_trust` (`trusted_internal` or `untrusted_external`) and `contains_injection`.
- `ScenarioSuite` (`scenarios_suite.json`) and `ReferenceOracle` (`reference_oracle.json`): Typed `Scenario` entries specifying `category`, `severity`, `is_adversarial`, `actor_role`, `expected_outcome`, `expected_reason_code`, `mitigation_id`, `proposed_plan`, optional `approval_service_override`, and optional `inject_canary_attempt`.
- `invalid_inputs.json`: Negative test fixtures covering unsupported schema version (`9.9.9`), negative trade notional (`-250.0`), unknown threat category, and real-looking non-synthetic canary values.

## 3. Canonical Output Contracts

### 3.1 `EvaluationReport` (`reports/baseline_evaluation.json`, `reports/latest_evaluation.json`)
- `schema_version`, `run_id`, `config_id`, `suite_id`, `agent_mode`
- `runtime_metadata`: `framework_version`, `python_version`, `platform`, SHA-256 hashes of config/suite/policy, `seed`, `recorded_at_utc`
- `summary`: `total_scenarios`, `adversarial_scenarios`, `benign_scenarios`, `passed_scenarios`, `failed_scenarios`, `attack_success_count`, `attack_success_rate`, `false_refusal_count`, `false_refusal_rate`, `canary_leak_count`, `within_tolerances`
- `category_metrics`: Map of `ThreatCategory -> CategoryMetrics` (per-category ASR, FRR, canary leaks)
- `diagnostic_counters`: Structured counts of tool calls, taint blocks, policy denials, canary blocks, approval outage blocks, and conflict blocks
- `verdicts`: Ordered list of `ScenarioVerdict` including full `tool_trace`, `actual_reason_codes`, `final_response_redacted`, and linked `audit_event_ids`
- `audit_events`: Redacted `AuditEvent` stream

### 3.2 `RegressionReport` (`reports/regression_report.json` & `.md`)
- `report_id`, `overall_status` (`PASS` / `FAIL`), `regressions_detected`, `open_findings`, `mitigated_findings`
- Guarded vs. unguarded ASR/FRR and `metric_deltas_vs_baseline`
- `findings`: List of `RegressionFinding` entries with `finding_id`, `severity`, `status` (`MITIGATED | OPEN | REGRESSED`), `mitigation_id`, `mitigation_description`, and exact CLI `reproduction_command`.

## 4. Validation & Operational Error Contract

| Exception Class | Trigger Condition | CLI Exit Code |
|---|---|---:|
| `ConfigurationError` | Missing config/fixture path or corrupt/unreadable JSON | `1` |
| `SchemaContractError` | Pydantic validation failure, unsupported `schema_version`, or violated safety invariant (`SYNTHETIC_CANARY_` / `ACC-SYNTH-`) | `1` |
| `UnsupportedInputError` | Unknown mock tool, unknown scenario ID, unsupported agent mode, or attempt to enable live external LLM provider | `1` |
| Tolerance / Oracle / Diff Failure | ASR, FRR, canary leak tolerance exceeded, oracle mismatch, or baseline regression detected | `2` |
