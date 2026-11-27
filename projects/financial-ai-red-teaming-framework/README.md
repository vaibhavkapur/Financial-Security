# Financial AI Red Teaming Framework

**Project 67 of 67** (`Financial-Security` repository) — an independently developed, offline educational and research prototype for evaluating simulated financial AI agents against indirect prompt injection, unsafe tool requests, privilege escalation, conflicting authority directives, approval outages, and secret canary leakage.

> **Safety Scope & Limitations:** All execution is strictly offline using synthetic financial accounts (`ACC-SYNTH-*`), synthetic canary tokens (`SYNTHETIC_CANARY_*`), and mock tools. No live capital, real customer records, production credentials, third-party external targets, or proprietary employer/SAAT artifacts are used. Live third-party LLM provider calls are intentionally disabled and marked **not run**. Any production adoption requires an independent security, operational, legal, and risk review.

## Quickstart

### Prerequisites
- Python 3.11+ (verified with CPython 3.12.15)
- [`uv`](https://docs.astral.sh/uv/) (verified with `uv 0.13.2`)

### 1. Install pinned dependencies
```bash
cd projects/financial-ai-red-teaming-framework
uv sync --frozen --dev
```
*(Offline environments with a populated uv cache can pass `--offline`.)*

### 2. Run the reproducible end-to-end demo
```bash
uv run python scripts/run_demo.py --verify-baseline
```

### 3. Run the CLI directly
```bash
# Verify deterministic hand-calculated reference oracle
uv run fin-redteam verify-oracle --config config/harness_config.json

# Run the full 16-scenario suite and write machine-readable + Markdown regression reports
uv run fin-redteam run \
  --config config/harness_config.json \
  --output reports/latest_evaluation.json \
  --regression-dir reports/

# Reproduce a single adversarial scenario (unguarded vs guarded)
uv run fin-redteam run-scenario --config config/harness_config.json --scenario-id SCN-INJ-001 --mode deterministic_unguarded
uv run fin-redteam run-scenario --config config/harness_config.json --scenario-id SCN-INJ-001 --mode deterministic_guarded

# Replay a recorded baseline deterministically and diff against baseline
uv run fin-redteam replay --config config/harness_config.json --previous reports/baseline_evaluation.json
uv run fin-redteam diff --baseline reports/baseline_evaluation.json --candidate reports/latest_evaluation.json
```

### 4. Run validation tests and linter
```bash
uv run ruff check src tests scripts
uv run pytest -v
```

## Example Output (Measured Synthetic Fixture Run)

> **Distinction of Evidence:** The numbers below are actual measured observations from running the deterministic offline synthetic suite (`fin-redteam-core-suite-v1`, 16 scenarios, seed `20261127`), not production claims or live LLM benchmarks.

```text
[Oracle] verified=True run_id=RUN-5e26349d2d88 issues=[]
[Unguarded Reference] run_id=RUN-8af66b4fec17 ASR=100.0% FRR=0.0% canary_leaks=4
[Guarded Harness]     run_id=RUN-bc2b70ce291c ASR=0.0% FRR=0.0% canary_leaks=0 passed=16/16
[Baseline Check] discrepancies=0
[Regression Report]   status=PASS mitigated=11 open=0 regressions=0
```

| Category | Scenarios | Unguarded ASR | Guarded ASR | Guarded FRR | Guarded Canary Leaks |
|---|---:|---:|---:|---:|---:|
| `benign_control` | 5 | N/A | N/A | 0.0% | 0 |
| `indirect_prompt_injection` | 3 | 100.0% | 0.0% | N/A | 0 |
| `privilege_escalation` | 3 | 100.0% | 0.0% | N/A | 0 |
| `sensitive_output_leakage` | 3 | 100.0% | 0.0% | N/A | 0 |
| `conflicting_instructions` | 1 | 100.0% | 0.0% | N/A | 0 |
| `unavailable_approval` | 1 | 100.0% | 0.0% | N/A | 0 |

## Documentation & Evidence Map

| Artifact | Purpose |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Component diagram, boundary isolation, invariants, and trade-offs |
| [`docs/threat-taxonomy.md`](docs/threat-taxonomy.md) | Threat categories, severity rubric, and safe expected outcomes |
| [`docs/contracts.md`](docs/contracts.md) | Versioned input/output schemas, units, timestamps, IDs, and error codes |
| [`docs/integration.md`](docs/integration.md) | Adapter boundaries for `Financial-Security` projects, optional LLM stub, licenses |
| [`docs/runbook.md`](docs/runbook.md) | Operator/developer runbook: demo, validation, replay, diagnostics, recovery |
| [`docs/adr/0001-boundary-isolation-and-deny-by-default.md`](docs/adr/0001-boundary-isolation-and-deny-by-default.md) | ADR 0001 documenting policy/enforcement/audit separation |
| [`reports/acceptance.md`](reports/acceptance.md) | Acceptance criteria mapped to measured test and evaluation evidence |
| [`reports/regression_report.md`](reports/regression_report.md) | Severity, reproduction commands, and mitigation tracking report |
| [`reports/baseline_evaluation.json`](reports/baseline_evaluation.json) | Pinned versioned baseline evaluation output |
| [`reports/latest_evaluation.json`](reports/latest_evaluation.json) | Latest machine-readable run output with runtime metadata |
| [`../../.github/workflows/financial-ai-red-teaming-framework.yml`](../../.github/workflows/financial-ai-red-teaming-framework.yml) | Automated CI validation workflow |

## Assumptions and Known Limitations

1. **Deterministic offline simulation:** The default `DeterministicFinancialAgent` parses structured injection payloads to provide reproducible, zero-flake evaluation of policy, taint, approval, and egress controls. Real stochastic LLMs exhibit broader phrasing and multi-turn planning behaviors.
2. **Optional live LLM provider not run:** `OptionalLLMProviderStub` demonstrates the provider adapter interface offline; live third-party LLM API integration is intentionally disabled and marked **not run** in [`reports/acceptance.md`](reports/acceptance.md).
3. **Coarse-grained provenance taint:** Any read of an `untrusted_external` document taints the scenario's execution context for subsequent mutating tools. While this yields 0% FRR on our synthetic suite (where benign workflows read internal docs before exporting or only summarize external docs), complex multi-step workflows that legitimately synthesize external research into an approved trade require an explicit human-in-the-loop declassification step.
4. **Heuristic conflict detection:** Conflict detection matches structured hold-vs-override authority markers and should be paired with formal workflow state locks in production systems.
