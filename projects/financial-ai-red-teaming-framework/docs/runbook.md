# Operator & Developer Runbook

## 1. Environment Setup (Clean Checkout)

```bash
cd projects/financial-ai-red-teaming-framework
uv sync --frozen --dev
```

Verify installation:
```bash
uv run fin-redteam --help
```

## 2. Standard Validation Workflow

Run linting, unit/integration/boundary tests, oracle verification, and baseline comparison:
```bash
uv run ruff check src tests scripts
uv run pytest -v
uv run fin-redteam verify-oracle --config config/harness_config.json
uv run python scripts/run_demo.py --verify-baseline
```

## 3. Generating & Updating Reports

### Refresh latest evaluation and regression reports
```bash
uv run python scripts/run_demo.py --write-reports --verify-baseline
```
This writes:
- `reports/latest_evaluation.json`
- `reports/unguarded_evaluation.json`
- `reports/regression_report.json`
- `reports/regression_report.md`

### Refreshing the pinned baseline (intentional policy or fixture updates only)
```bash
uv run python scripts/capture_baseline.py --config config/harness_config.json --output reports/baseline_evaluation.json
```
Always inspect `git diff reports/baseline_evaluation.json` and document any intentional tolerance or fixture changes before committing.

## 4. Reproducing Findings & Replaying Runs

### Reproduce an individual scenario
Every finding in `reports/regression_report.md` lists an exact reproduction command:
```bash
uv run fin-redteam run-scenario --config config/harness_config.json --scenario-id SCN-INJ-001 --mode deterministic_unguarded
uv run fin-redteam run-scenario --config config/harness_config.json --scenario-id SCN-INJ-001 --mode deterministic_guarded
```

### Deterministic replay of a previous evaluation
```bash
uv run fin-redteam replay --config config/harness_config.json --previous reports/baseline_evaluation.json
```
Expected output: `"replay_match": true` with identical `run_id` and `diagnostic_counters`.

## 5. Diagnostics & Recovery Procedures

| Symptom / Failure Mode | Root Cause | Diagnostic Signal | Recovery Step |
|---|---|---|---|
| CLI exits with code `1` and `ConfigurationError` | Missing or corrupt `harness_config.json` or fixture file | Error message prints exact missing/corrupt path | Restore missing file from repository checkout or pass valid `--config <path>` |
| CLI exits with code `1` and `SchemaContractError` | Unsupported `schema_version`, negative monetary amount, or non-synthetic canary/account ID | Pydantic validation error identifies field and violated rule | Fix schema version to `"1.0.0"`, enforce `SYNTHETIC_CANARY_` / `ACC-SYNTH-` prefixes, and re-run `pytest` |
| CLI exits with code `1` and `UnsupportedInputError` | Unknown scenario ID, unknown tool name, or `live_enabled=True` on optional LLM stub | Explicit error naming unsupported input | Use a valid scenario ID from `data/fixtures/scenarios_suite.json` and keep offline stub mode enabled |
| CLI exits with code `2` on `verify-oracle` or `diff` | Behavioral regression in policy, taint tracking, approval gating, or canary filter | Discrepancy list names regressed `scenario_id` and changed `reason_code` | Run `fin-redteam run-scenario --scenario-id <ID>` to inspect `tool_trace` and `audit_events`, fix control, and re-verify |
| `diagnostic_counters["approval_outage_blocks"]` elevated | Approval backend set to `unavailable` in config or scenario override | `APPROVAL_UNAVAILABLE` audit events | Confirm whether outage simulation is intentional; restore `approval_service.default_status = "online"` in `config/harness_config.json` |
