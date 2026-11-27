# Trading Infrastructure Security Monitor (TISM)

Defensive security lab prototype that ingests synthetic trading infrastructure telemetry (`auth_log`, `config_diff`, `deployment_audit`, `order_audit`), normalizes schemas and redacts secrets, detects unauthorized privilege/configuration/deployment/order anomalies with Sigma-style YAML rules and stateful detectors, correlates alerts into evidence-backed cases, and produces reviewer-approved **simulation-only** containment proposals with a tamper-evident audit chain.

> **Scope & Safety Notice:** Independently developed educational/research prototype using 100% synthetic offline fixtures. **No live trading systems, real transactions, customer records, production credentials, or automatic live containment** are included.

## Project Layout

```text
projects/trading-infrastructure-security-monitor/
├── config/
│   ├── monitor_config.json         # Runtime settings (simulation_only, seed, windows)
│   ├── policy.json                 # Deny-by-default tickets, roles, CIDRs, reviewers, suppressions
│   ├── redaction_policy.json       # Sensitive keys & inline secret regex rules
│   ├── postgres_schema.sql         # Reference PostgreSQL DDL schema
│   └── rules/                      # Sigma-style YAML detection rules (TISM-SIGMA-001..005)
├── data/fixtures/
│   ├── reference/                  # Deterministic fixture + hand-calculated expected_oracle.json
│   ├── scenarios/                  # Domain, resilience, suppression/audit, and synthetic eval datasets
│   └── invalid/                    # Malformed & unsupported events for fail-closed tests
├── docs/
│   ├── architecture.md             # Mermaid component diagram, boundaries, invariants, trade-offs
│   ├── contracts.md                # Canonical input/output schemas, units, versions, typed errors
│   ├── integration.md              # Adapter boundaries, sibling repo context, licenses & provenance
│   ├── runbook.md                  # Operator/developer commands, replay, diagnostics & recovery
│   └── adr/0001-architecture-and-stack.md
├── reports/
│   ├── acceptance.md               # Acceptance criteria mapped to observed tests & benchmarks
│   ├── baseline_reference.json     # Versioned baseline oracle run output
│   ├── evaluation_metrics.json     # Measured recall, precision, FP/FN, provenance & live-guard check
│   ├── integration_resilience.json # Missing telemetry & duplicate log scenario output
│   ├── containment_review_audit.json # Suppression expiry & hash-chained reviewer audit output
│   ├── demo_reviewed_report.json   # Full demo report with dual-control containment simulation
│   └── demo_otel_telemetry.json    # Redacted OTLP/JSON spans and diagnostic counters
├── scripts/                        # run_demo.sh, validate.sh, generate_reports.sh
├── src/                            # Typed Go packages + CLI (src/cmd/tism)
├── tests/                          # Integration, Sigma regression, boundary, acceptance & benchmarks
├── Makefile
├── go.mod                          # Zero third-party runtime dependencies (Go stdlib only)
└── plan.md
```

## Quickstart & Setup

Requires **Go 1.24+** (verified on Go `1.27.1`, `darwin/arm64`). No external network access or database server is needed.

```bash
cd projects/trading-infrastructure-security-monitor

# Build CLI binary and validate config + Sigma rules
make build
./bin/tism validate-config --config config/monitor_config.json

# Run the end-to-end demo (detection, correlation, dual-control simulation review, evaluation)
./scripts/run_demo.sh

# Run full validation suite (go vet + race-enabled unit, integration, regression & acceptance tests)
./scripts/validate.sh

# Run microbenchmarks
make bench
```

## Example Demo Output (Observed)

```text
==> [1/3] Validating monitor configuration and Sigma rules...
Configuration valid: env=synthetic-trading-lab rules=5 containment_mode=simulation_only live_containment=false
==> [2/3] Running end-to-end synthetic security monitoring demo (simulation-only containment)...
RunID=RUN-868cf7d7801e | Ingested=22 Normalized=21 Dedup=1 Invalid=0 RedactedFields=2 | Gaps=0 | Alerts=8 (Active=8 Suppressed=0) | Cases=4 | Proposals=7 (Live=false)
Containment Simulation Review: 7 proposal(s) reviewed & simulated (live_executed=false); audit_chain=19 records VERIFIED
==> [3/3] Evaluating synthetic detection recall and false-positive rate...
Evaluation [synthetic-trading-eval-v1]: TP=8 FP=0 FN=0 Recall=1.0000 Precision=1.0000 F1=1.0000 Traced=true LiveContainment=0
```

## Acceptance Evidence & Documentation

- **Acceptance Report:** [`reports/acceptance.md`](reports/acceptance.md)
- **Measured Synthetic Evaluation:** [`reports/evaluation_metrics.json`](reports/evaluation_metrics.json) (`Recall=1.0000`, `FP=0`, `AllAlertsTraced=true`, `LiveContainmentCount=0`)
- **Architecture & Boundaries:** [`docs/architecture.md`](docs/architecture.md) and [`docs/adr/0001-architecture-and-stack.md`](docs/adr/0001-architecture-and-stack.md)
- **Data Contracts:** [`docs/contracts.md`](docs/contracts.md)
- **Integration & Provenance:** [`docs/integration.md`](docs/integration.md)
- **Runbook & Recovery:** [`docs/runbook.md`](docs/runbook.md)
- **CI Validation Workflow:** [`../../.github/workflows/trading-infrastructure-security-monitor.yml`](../../.github/workflows/trading-infrastructure-security-monitor.yml)

## Assumptions and Known Limitations

- **Synthetic Lab Only:** All recall/precision measurements (`Recall=1.0`, `FP=0`) reflect synthetic labeled scenarios in `data/fixtures/scenarios/synthetic_eval_dataset.jsonl` and must not be interpreted as production detection guarantees.
- **No Live Containment:** Automatic and live containment actions are permanently blocked (`ErrLiveContainmentProhibited`). Containment proposals only emit dry-run simulated diffs after authorized human review (and dual control for `critical` cases).
- **Offline Storage & Telemetry:** `store.PostgresStore` and OTLP collector shipping are provided as typed adapters/schemas (`config/postgres_schema.sql`, `src/telemetry/otel.go`) and are explicitly marked **Not Run** against live external infrastructure in [`reports/acceptance.md`](reports/acceptance.md).
- **Sigma YAML Subset:** The embedded zero-dependency Sigma parser supports the rule constructs used in `config/rules/` (`logsource`, selections/filters, field modifiers `|contains`, `|startswith`, `|endswith`, `|in`, `|re`, `|neq`, boolean operators, and `1 of`/`all of` quantifiers) rather than full YAML 1.2 anchors/merges.
