# Acceptance Evidence Report — Agent Identity and Authorization Platform (AIAP)

- **Schema Version:** `1.0.0`
- **Policy Version:** `aiap-policy-v1.0.0`
- **Configuration:** `config/default.json` (`EdDSA`, `deny_by_default: true`, `max_delegation_depth: 2`, `clock_skew_seconds: 0`, `random_seed: 20261127`)
- **Measured Environment:** Go `go1.27.1`, `darwin/arm64`, Apple M5 (10 CPUs), SQLite (`modernc.org/sqlite v1.60.1`)
- **Scope Notice:** All tests and evaluations use 100% synthetic fixtures and simulated financial actions. No live capital, real customer records, or production credentials were used.

---

## 1. Test and Validation Matrix Evidence

| Test Area | Required Scenario | Automated Verification | Raw Machine-Readable Evidence | Measured Observation |
|---|---|---|---|---|
| **Domain correctness** | Expired grant, audience mismatch, altered amount | `TestCanonicalDigestOracleAndDeterminism`, `TestDomainCore_ExpiredGrant_AudienceMismatch_AlteredAmount`, `TestJWTAlgorithmDowngradeRejected`, `TestBoundaryAndInvalidFixtures` | `reports/baseline_outputs.json` (`REF-01`..`REF-09`) | **PASS** — 9/9 reference fixture steps match hand-calculated expected decisions, reason codes, and remaining minor-unit balances; independent SHA-256 oracle matches canonical digest; `alg: none` and `HS256` downgrade blocked (`ERR_TOKEN_INVALID_ALG`). |
| **Integration and resilience** | Revocation race and duplicate approval | `TestIntegration_RevocationRaceLinearizable`, `TestIntegration_DuplicateApprovalConcurrentAndSequential`, `TestIntegration_PersistenceAcrossRestartAndReportGeneration` (all run under `go test -race`) | `reports/integration_report.json` | **PASS** — 30-worker concurrent revocation race achieved strict linearizability (`0` post-revocation `ALLOW`s, `31` replayed decisions verified); 20-worker duplicate approval race allowed exactly `1` request and denied `19` with `ERR_APPROVAL_ALREADY_USED`; state persisted across SQLite restart. |
| **Boundary and failure behavior** | Delegation escalation | `TestAdversarial_DelegationEscalationSuiteAndReproducibility`, `TestAdversarial_SubDelegationCumulativeCapChainEnforcement`, `TestAdversarial_AuditTamperDetection` | `reports/adversarial_report.json` (`ADV-01`..`ADV-16`) | **PASS** — 16/16 adversarial cases blocked with exact reason codes (`ADV-01`..`ADV-08` cover scope, per-action cap, cumulative remaining cap, approval threshold, expiry, audience, counterparty drop, non-delegable parent, and depth overflow); 20/20 seeded payload mutations blocked; SQLite audit row tampering detected (`ERR_AUDIT_TAMPER_DETECTED`). |
| **Reproducibility** | Same versioned inputs/configuration and fixed seed | `TestAdversarial_DelegationEscalationSuiteAndReproducibility` (two back-to-back runs with `seed=20261127`), `verify-fixtures` | `reports/baseline_outputs.json`, `reports/adversarial_report.json` | **PASS** — Byte-for-byte identical JSON outputs across consecutive fixed-seed adversarial runs; deterministic `action_digest` and `audit_entry_hash` in reference fixture runs. |
| **Operational review** | Missing configuration, unsupported inputs, restart/rerun | `TestOperational_MissingAndInvalidConfigurationFailsClosed`, `TestOperational_UnsupportedDomainInputsRejected`, `TestIntegration_PersistenceAcrossRestartAndReportGeneration` | `reports/integration_report.json` | **PASS** — Missing file, malformed JSON, unknown fields, `deny_by_default: false`, non-`EdDSA` algorithms, bare `*` wildcard scopes, self-delegation, and agent root grants fail closed with explicit `ERR_*` codes; restart recovery verified on disk-backed SQLite. |

---

## 2. Project-Specific Acceptance Criteria Mapping

| Criterion | Status | Evidence |
|---|---|---|
| No action outside scope or after revocation policy | **PASS** | `REF-06`, `REF-08`, `ADV-10`, `ADV-15`, `TestIntegration_RevocationRaceLinearizable` (`post_revocation_allows = 0`). |
| Approval cannot be reused | **PASS** | `REF-04`, `ADV-14`, `TestIntegration_DuplicateApprovalConcurrentAndSequential` (`1` allow / `19` `ERR_APPROVAL_ALREADY_USED` concurrently + sequential denial). |
| All decisions traceable | **PASS** | Every `ALLOW` and `DENY` writes a redacted, SHA-256 hash-chained `AuditEvent` with `ReplayEnvelope`; verified by `audit.ReplayAuditLog` across `baseline_outputs.json` (11 events / 9 decisions), `adversarial_report.json`, and `TestTelemetryRedactionPreservesReplay`. |
| All required test scenarios pass in the supported environment, or unavailable dependencies marked not run | **PASS** | All Go unit, integration (`-race`), adversarial, operational, and fixture tests pass locally; live PostgreSQL execution is explicitly marked **NOT RUN** below. |
| README documents setup, demo, validation, assumptions, and known limitations | **PASS** | Documented in `README.md`, `docs/architecture.md`, `docs/contracts.md`, `docs/integration.md`, and `docs/runbook.md`. |
| No real transactions, customer data, credentials, or proprietary employer/SAAT artifacts | **PASS** | Verified across all source, fixture, config, and report files (synthetic `mock-*` identifiers and labeled test key seeds only). |

---

## 3. Measured Microbenchmark Observations

Captured via `go test -run=^$ -bench=. -benchmem -count=1 ./tests/...` on `darwin/arm64` (Apple M5, Go 1.27.1) and archived in `reports/benchmark_raw.txt`:

| Benchmark | Measured Latency (`ns/op`) | Throughput (approx.) | Memory (`B/op`) | Allocations (`allocs/op`) | Notes |
|---|---:|---:|---:|---:|---|
| `BenchmarkGrantSignAndVerify` | `43,952 ns/op` (~44.0 µs) | ~22,750 ops/sec | `11,045 B/op` | `91` | Full Ed25519 JWT sign + EdDSA parse/verify |
| `BenchmarkAuthorizeEndToEnd` | `110,839 ns/op` (~110.8 µs) | ~9,020 ops/sec | `25,747 B/op` | `391` | EdDSA verify + SQLite `BEGIN IMMEDIATE` TX + revocation check + policy eval + SHA-256 audit chain append |
| `BenchmarkAuditReplay100Events` | `522,501 ns/op` (~522.5 µs / 100 events) | ~191,380 events/sec | `534,551 B/op` | `4,580` | Full hash-chain verification + pure policy replay of 100 events |

> These are local single-machine measurements on synthetic in-memory SQLite fixtures, not production SLA guarantees.

---

## 4. Explicitly Untested / Out-of-Scope Capabilities

| Capability | Status | Reason |
|---|---|---|
| Live PostgreSQL (`pgx/v5`) execution (`src/store/postgres.go`, `config/schema/postgres.sql`) | **NOT RUN (compiled only)** | No local PostgreSQL daemon (`psql`) installed in the offline test environment; schema and `pgxpool` adapter compile cleanly under `go build ./...` and `go vet ./...`. |
| Hardware Security Module (HSM) / KMS key custody & live key rotation | **OUT OF SCOPE** | Prototype uses synthetic Ed25519 keys per `plan.md` scope limitations. |
| Production financial settlement, live capital, real customer records | **OUT OF SCOPE** | Mock simulated actions only. |
