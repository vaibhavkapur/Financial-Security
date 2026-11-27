# Acceptance & Validation Evidence — Trading Infrastructure Security Monitor

**Runtime Environment (Observed):** Go `go1.27.1` on `darwin/arm64` (Apple M5)  
**Configuration:** `config/monitor_config.json` (`schema_version=1.0.0`, `deterministic_seed=2026065`, `containment_mode=simulation_only`, `live_containment_enabled=false`)  
**Validation Command:** `./scripts/validate.sh && ./scripts/generate_reports.sh && make bench`

> **Observation vs. Target Distinction:** All metrics below are **measured observations** from executing the deterministic synthetic fixtures in `data/fixtures/` under the offline defensive lab configuration, not production guarantees or live trading telemetry measurements.

## 1. Project-Specific Acceptance Criteria (`plan.md` §5)

| Acceptance Criterion | Status | Measured Evidence & Raw Artifacts |
|---|---|---|
| Synthetic detection recall and false-positive counts reported | **PASS** | `reports/evaluation_metrics.json` (`synthetic-trading-eval-v1`, RunID `RUN-868cf7d7801e`): **TP=8, FP=0, FN=0, Recall=1.0000, Precision=1.0000, F1=1.0000** across 22 ingested events (21 unique normalized, 1 duplicate deduplicated, 2 sensitive fields redacted). Automated in `tests/acceptance_bench_test.go` (`TestAcceptanceCriteriaSyntheticEvaluation`). |
| Alerts trace to source events | **PASS** | `all_alerts_traced: true` in `reports/evaluation_metrics.json`; every alert across `reports/baseline_reference.json`, `reports/integration_resilience.json`, `reports/containment_review_audit.json`, and `reports/demo_reviewed_report.json` carries non-empty `source_event_ids` and correlated `Case.source_event_ids`. |
| No automatic live containment | **PASS** | `live_containment_count: 0` in `reports/evaluation_metrics.json`; `live_containment: false` across all reports; `MonitorConfig.Validate()` and `Simulator.ExecuteLive()` unconditionally return `ErrLiveContainmentProhibited` (`TestMonitorConfigProhibitsLiveContainment`, `TestContainmentSimulationDualControlAndAuditChain`, `TestOperationalFailureModesNoSilentSuccess`). |
| All required test scenarios pass (or unavailable dependencies marked not run) | **PASS** | All 10 Go packages pass `go vet` and `go test -race -count=1 ./...` (see §2 & §3 below; live PostgreSQL/OTLP collector integrations explicitly marked `Not Run` in §4). |
| README documents setup, demo, validation, assumptions, and limitations | **PASS** | Documented in `README.md`, `docs/architecture.md`, `docs/contracts.md`, `docs/integration.md`, `docs/runbook.md`, and `docs/adr/0001-architecture-and-stack.md`. |
| No real transactions, customer data, credentials, or proprietary employer/SAAT artifacts | **PASS** | All fixtures are synthetic RFC 5737 / RFC 1918 lab records (`SYNTH_*`, `CHG-2026-*`, `synthetic-*`, `tism_sim_*`); redaction tests assert zero raw secret leakage into reports or OTLP spans (`TestNormalizeAndRedactSecrets`, `TestReferenceFixtureMatchesHandCalculatedOracle`, `TestAcceptanceCriteriaSyntheticEvaluation`). |

## 2. Test & Validation Matrix Evidence (`plan.md` §4)

| Test Area | Required Scenario | Automated Test(s) | Raw Report / Observed Result |
|---|---|---|---|
| Domain correctness | Authorized deployment vs unexpected config edit | `src/detector/detector_test.go::TestAuthorizedDeploymentVsUnexpectedConfigEdit`, `tests/integration_test.go::TestDomainAuthorizedDeploymentVsUnexpectedConfigScenario`, `tests/integration_test.go::TestReferenceFixtureMatchesHandCalculatedOracle` | `reports/baseline_reference.json` (`RUN-534dce8bd75e`) matches `data/fixtures/reference/expected_oracle.json` exactly (0 deviations). |
| Integration & resilience | Missing telemetry and duplicate logs | `tests/integration_test.go::TestIntegrationMissingTelemetryAndDuplicateLogs` | `reports/integration_resilience.json` (`RUN-91ab70dfe262`): 6 ingested → 4 normalized, 2 deduplicated (1 config alert, zero duplicate inflation), 2 telemetry gaps detected (`order_audit` missing + `auth_log` 720s silence gap). |
| Boundary & failure behavior | False-positive suppression and reviewer audit | `tests/boundary_failure_test.go::TestBoundaryFalsePositiveSuppressionAndReviewerAudit`, `src/containment/simulator_test.go` | `reports/containment_review_audit.json` (`RUN-7b5c1c5dd1d9`): pre-expiry off-hours alert suppressed & audited; post-expiry alert fails closed and fires; self-approval and unauthorized reviewers rejected; dual-control enforced on critical proposal; 4-record SHA-256 audit chain verified; tamper test triggers `ErrAuditChainTampered`. |
| Rule regression | All 5 Sigma-style YAML rules (TP, benign near-miss, boundary) | `tests/rule_regression_test.go::TestSigmaRuleRegressionMatrix` (12 subtests across `TISM-SIGMA-001`..`005`) | 12/12 subtests pass with `-race`. |
| Reproducibility | Same versioned inputs/config/seed + replay | `tests/integration_test.go::TestReproducibilityIdenticalLogicalOutputsAcrossReruns`, `src/pipeline/pipeline_test.go::TestPipelineEndToEndAndReplayDeterminism` | Byte-identical `RunReport` and `OTLPExport` JSON across independent runs and normalized JSONL replay. |
| Operational review | Missing config, invalid config, live-mode config, unsupported/malformed inputs | `tests/boundary_failure_test.go::TestOperationalFailureModesNoSilentSuccess`, `src/contracts/types_test.go` | Missing config returns `ErrMissingConfig`; live mode returns `ErrLiveContainmentProhibited`; `data/fixtures/invalid/invalid_events.jsonl` surfaces all 5 errors explicitly in `validation_errors` with 0 silent drops. |

## 3. Measured Microbenchmarks

Executed via `GOCACHE=/tmp/tism-gocache go test -run=^$ -bench=. -benchmem ./tests/...` on `darwin/arm64` (Apple M5, Go 1.27.1):

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|---|---:|---:|---:|---:|
| `BenchmarkPipelineSyntheticEval-10` (22-event end-to-end JSONL ingest + redact + Sigma/stateful detect + correlate + propose + OTLP) | 6,090 | 195,793 | 212,390 | 1,387 |
| `BenchmarkRedactionEngine-10` (nested payload key + regex redaction + SHA-256 fingerprint) | 111,228 | 10,809 | 1,488 | 29 |

## 4. Explicitly Untested / Not-Run Capabilities

| Capability | Status | Reason & Boundary |
|---|---|---|
| Live PostgreSQL persistence (`store.PostgresStore` against running Postgres server) | **Not Run** | Offline lab environment has no live PostgreSQL instance or external SQL driver binary. Schema DDL (`config/postgres_schema.sql`) and `database/sql` adapter compile cleanly, and nil-DB fail-fast behavior is tested in `TestPostgresStoreRejectsNilDB`. |
| Live OTLP gRPC/HTTP collector shipping | **Not Run** | Offline lab has no external OpenTelemetry collector endpoint. Redacted OTLP/JSON export structure is verified offline (`reports/demo_otel_telemetry.json`, `TestRecorderRedactsSpanAttributesAndDeterministicTraceID`). |
| Live containment execution against infrastructure | **Prohibited / Out of Scope** | Permanently disabled by design (`ErrLiveContainmentProhibited`). Any production integration requires separate security, operational, legal, and risk review. |
