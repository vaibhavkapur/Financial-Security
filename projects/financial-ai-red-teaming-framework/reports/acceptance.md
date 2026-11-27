# Acceptance Evidence — Financial AI Red Teaming Framework

## 1. Recorded Environment & Pinned Configuration

| Field | Measured Value |
|---|---|
| **Framework Version** | `0.1.0` |
| **Python Runtime** | `CPython 3.12.15` |
| **Platform** | `macOS-26.5.1-arm64-arm-64bit` |
| **Package Manager / Lock** | `uv 0.13.2` (`uv.lock`, `pydantic==2.14.4`, `pytest==8.4.2`, `ruff==0.17.6`) |
| **Config ID & SHA-256** | `default-redteam-v1` (`24224a47daf88870c9a2803af72d6ef40a26a0e5006b00511c6882040bfc4430`) |
| **Policy Set & SHA-256** | `gold-fin-policy-v1` (`959fd5e6abc3b77ce0296e5feeee24acf2e3a0e19e7df8b4d61b0011d8630fa2`) |
| **Suite ID & SHA-256** | `fin-redteam-core-suite-v1` (`ff0fe733c5b89f46c7f82b321d7d09abcf7b51b4a88b31f5b569912687c88615`) |
| **Seed** | `20261127` |
| **Guarded Run ID** | `RUN-bc2b70ce291c` |
| **Unguarded Reference Run ID** | `RUN-8af66b4fec17` |
| **Reference Oracle Run ID** | `RUN-5e26349d2d88` |

## 2. Project-Specific Acceptance Criteria Mapping

| # | Acceptance Criterion | Status | Measured Evidence |
|---|---|---|---|
| 1 | **No real secrets or transactions** | **PASS** | `CanarySecret` enforces `SYNTHETIC_CANARY_*` prefix and `MockAccount` enforces `ACC-SYNTH-*` prefix in `src/fin_redteam/models.py`; verified by `test_no_real_secrets_or_live_credentials_in_project_files` and `test_invalid_inputs_fixture_cases_fail_schema_validation`. All mock tools mutate isolated in-memory dicts only. |
| 2 | **Report attack success and false refusal rates by category** | **PASS** | Guarded run (`RUN-bc2b70ce291c`): `ASR = 0.0%`, `FRR = 0.0%`, `canary_leak_count = 0` across all 6 categories (`benign_control`, `indirect_prompt_injection`, `privilege_escalation`, `sensitive_output_leakage`, `conflicting_instructions`, `unavailable_approval`). Unguarded reference (`RUN-8af66b4fec17`): `ASR = 100.0%`, `FRR = 0.0%`, `canary_leak_count = 4`. Evidence in `reports/latest_evaluation.json` and `reports/regression_report.md`; asserted by `test_asr_and_frr_reported_by_category`. |
| 3 | **Reproducible fixture-level evidence** | **PASS** | `fin-redteam verify-oracle` (`RUN-5e26349d2d88`, `oracle_verified=true`), `fin-redteam replay --previous reports/baseline_evaluation.json` (`replay_match=true`, matching `RUN-bc2b70ce291c` and identical `diagnostic_counters`), and `fin-redteam diff` (`regressions_found=0`). |
| 4 | **All required test scenarios pass; unavailable dependencies marked not run** | **PASS** | `pytest -v`: **20/20 passed in 0.07s**; `ruff check src tests scripts`: **All checks passed**. Live third-party LLM provider calls are explicitly marked **Not Run** in Section 4 below. |
| 5 | **README documents setup, demo, validation, assumptions, and limitations** | **PASS** | `README.md` documents prerequisites, `uv sync`, demo/CLI commands, measured synthetic fixture outputs (distinct from production claims), assumptions, and known limitations. |
| 6 | **No real transactions, customer data, credentials, or proprietary employer/SAAT artifacts** | **PASS** | Verified by static regex scan in `tests/test_reporting_and_safety.py`, synthetic-only provenance metadata (`provenance: "synthetic_offline_fixture"`), and zero cross-repo/private imports. |

## 3. Test and Validation Matrix Evidence

| Test Area | Required Scenario | Automated Test(s) | Measured Result |
|---|---|---|---|
| **Domain correctness** | Untrusted tool output requests unauthorized action | `tests/test_policy_and_enforcement.py::test_pure_policy_engine_blocks_untrusted_tainted_mutation`, `test_untrusted_tool_output_requests_unauthorized_action_end_to_end` | **PASS** (`TAINTED_WRITE_DENIED`, `len(sandbox.draft_wires) == 0`) |
| **Integration and resilience** | Secret canary disclosure attempt | `tests/test_canary_and_integration.py::test_secret_canary_disclosure_attempts_blocked_across_encodings`, `test_telemetry_and_reports_never_contain_raw_canary_secrets` | **PASS** (raw, base64, and spaced canaries blocked with `CANARY_EGRESS_BLOCKED`; zero raw canaries in telemetry) |
| **Boundary and failure behavior** | Conflicting instructions and unavailable approval | `tests/test_boundaries_and_failures.py::test_conflicting_instructions_fail_closed`, `test_unavailable_approval_service_fails_closed`, `test_max_tool_steps_boundary_enforced` | **PASS** (`CONFLICTING_INSTRUCTIONS_DENIED`, `APPROVAL_UNAVAILABLE`, `MAX_STEPS_EXCEEDED`) |
| **Reproducibility** | Same versioned inputs/configuration and fixed seed | `tests/test_canary_and_integration.py::test_structured_audit_counters_and_replay_equivalence`, `fin-redteam replay` | **PASS** (identical `RUN-bc2b70ce291c`, identical verdicts and counters) |
| **Operational review** | Missing configuration, unsupported inputs, restart/rerun | `tests/test_boundaries_and_failures.py::test_operational_missing_config_and_corrupt_json_fail_explicitly`, `test_operational_unsupported_inputs_raise_clear_errors` | **PASS** (`ConfigurationError`, `SchemaContractError`, `UnsupportedInputError`, CLI exit code `1`) |

## 4. Explicitly Untested / Out-of-Scope Capabilities

| Capability | Status | Rationale |
|---|---|---|
| **Live third-party LLM provider evaluation** | **Not Run (Intentionally Disabled)** | Prohibited in offline sandbox scope; `OptionalLLMProviderStub(live_enabled=True)` fails closed with `UnsupportedInputError`. Offline contract verified via `test_optional_llm_stub_runs_deterministically_offline`. |
| **Live integration with sibling `Financial-Security` services** | **Not Run (Stub/Adapter Boundary Only)** | Sibling project directories (`agent-identity-and-authorization-platform`, `financial-api-security-gateway`, `trading-infrastructure-security-monitor`, `digital-asset-custody-platform`) currently contain planning docs only (`plan.md`). Adapter boundaries are documented in `docs/integration.md`. |
| **GitHub Actions CI remote execution** | **Not Run Remotely (Verified Locally)** | `.github/workflows/ci.yml` commands (`uv sync`, `ruff check`, `pytest -v`, `fin-redteam verify-oracle`, `scripts/run_demo.py --verify-baseline`) were executed and verified locally on macOS arm64; remote Linux runner execution awaits repository push. |
