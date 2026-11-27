# Agent Identity and Authorization Platform (AIAP)

> **Scope Notice:** Independently developed educational and research prototype for issuing and enforcing bounded delegated permissions for **simulated financial agents** (mock actions only). Live capital, real customer records, and production credentials are strictly excluded.

## Overview

AIAP issues short-lived, cryptographically signed delegation grants (**Ed25519 / RFC 8037 EdDSA JWTs** via `github.com/golang-jwt/jwt/v5`) and enforces **deny-by-default** authorization boundaries for simulated financial agents:

- **Actor / Delegator Identity & Scope Contracts (`src/domain`):** Pure, I/O-free domain validation, integer minor-unit monetary limits (no floats), explicit resource allowlists (bare `*` wildcards prohibited), and strict monotonic sub-delegation attenuation that prevents delegation escalation.
- **Short-Lived Signed Grants (`src/crypto`):** EdDSA (Ed25519) signed JWT grants bound to issuer, actor, audience, scopes, spending limits, approval thresholds, and TTL, with strict algorithm pinning (`EdDSA` only; rejects `alg: none` and HMAC downgrade attempts).
- **Atomic Enforcement, Revocation & Exact-Action Approvals (`src/enforcer`, `src/store`):** Serialized ACID transactions (`SQLite` default via `modernc.org/sqlite`; runnable `PostgreSQL` adapter via `github.com/jackc/pgx/v5`) providing linearizable revocation-race protection, cascading ancestor revocation, chain-wide cumulative spending enforcement, and single-use Ed25519 approvals bound to the canonical SHA-256 digest of the exact action payload.
- **Redacted Audit Replay & Adversarial Evaluation (`src/audit`):** Redacted structured telemetry, tamper-evident SHA-256 hash-chained audit logs, deterministic policy decision replay, and a fixed-seed adversarial delegation evaluation suite.

## Repository Layout

```text
projects/agent-identity-and-authorization-platform/
├── plan.md                              # Original implementation plan
├── go.mod / go.sum                      # Pinned Go dependencies
├── config/
│   ├── default.json                     # Pinned runtime policy configuration
│   └── schema/{sqlite,postgres}.sql     # ACID persistence schemas
├── data/fixtures/
│   ├── reference_scenario.json          # Deterministic M1/M2 reference scenario + expected outcomes
│   └── boundary_and_invalid.json        # Boundary and negative validation vectors
├── src/
│   ├── config/                          # Fail-closed configuration loader & validator
│   ├── domain/                          # I/O-free contracts, canonical digest, pure policy engine
│   ├── crypto/                          # Ed25519 keys, JWK export, EdDSA JWT signer/verifier
│   ├── store/                           # ACID Store interface + SQLite (default) & PostgreSQL adapters
│   ├── enforcer/                        # PlatformService (PDP/PEP, revocation, single-use approvals)
│   ├── audit/                           # Hash-chained audit replay + seeded adversarial suite
│   └── cmd/agent-authz/                 # CLI (demo, verify-fixtures, evaluate, inspect-config)
├── tests/                               # Unit, concurrency (-race), adversarial, operational & benchmarks
├── scripts/
│   ├── demo.sh                          # One-command reproducible demo
│   └── validate.sh                      # Full vet/build/race-test/fixture/adversarial/benchmark pipeline
├── docs/
│   ├── architecture.md                  # Mermaid diagrams, boundaries, invariants & trade-offs
│   ├── contracts.md                     # Canonical schemas, minor units, timestamps & error codes
│   ├── integration.md                   # Sibling repo adapter boundaries, licenses & fixture provenance
│   ├── runbook.md                       # Operator/developer diagnostics & recovery guide
│   └── adr/0001-stack-and-boundaries.md # Architecture Decision Record
└── reports/
    ├── acceptance.md                    # Acceptance criteria mapped to automated test & benchmark evidence
    ├── baseline_outputs.json            # Reference fixture machine-readable results
    ├── integration_report.json          # Concurrency, revocation race & restart persistence results
    ├── adversarial_report.json          # Seeded adversarial delegation evaluation results
    └── benchmark_raw.txt                # Raw measured Go benchmark outputs
```

## Quickstart

**Prerequisites:** Go 1.26+ (verified locally on Go 1.27.1, `darwin/arm64`). No external database daemon is required for default SQLite mode.

### 1. Run the End-to-End Demo
```bash
cd projects/agent-identity-and-authorization-platform
./scripts/demo.sh
```

**Observed Demo Output (synthetic fixtures):**
```text
=== Agent Identity & Authorization Platform (AIAP) Demo ===
Policy: aiap-policy-v1.0.0 | Issuer: aiap-authority.mock.local | Alg: EdDSA | Scope: Simulated Mock Actions Only

[1] Issued Root Grant grt-demo-root (actor=agent.rebalancer.01, cap=$1000.00, approval>$150.00, ttl=300s)
[2] Issued Attenuated Sub-Grant grt-demo-sub (depth=1, actor=agent.subexec.02, cap=$300.00, ttl=180s)
[3] Payment $100.00 -> ALLOW (ALLOW_AUTHORIZED) remaining=$900.00
[4] Tampered $250.01 vs $250.00 Approval -> DENY (ERR_APPROVAL_PAYLOAD_MISMATCH)
[5] Exact-Action Approved $250.00 -> ALLOW (ALLOW_AUTHORIZED) remaining=$650.00
[6] Reused Approval Replay -> DENY (ERR_APPROVAL_ALREADY_USED)
[7] Sub-Grant Action After Root Revocation -> DENY (ERR_GRANT_REVOKED)

[8] Audit Replay: events=8 verified_decisions=5 chain_valid=true passed=true
```

### 2. Run Full Validation, Race Tests, Adversarial Suite, and Benchmarks
```bash
./scripts/validate.sh
```

Or invoke individual checks directly:
```bash
go vet ./...
go build ./...
go test -race -v -count=1 ./tests/...
go run ./src/cmd/agent-authz verify-fixtures --config config/default.json --fixture data/fixtures/reference_scenario.json
go run ./src/cmd/agent-authz evaluate --config config/default.json
```

## Acceptance Evidence and Measured Results

Full acceptance criteria mapping and raw evidence are recorded in [`reports/acceptance.md`](reports/acceptance.md):

- **Reference Fixtures ([`reports/baseline_outputs.json`](reports/baseline_outputs.json)):** 9/9 steps pass with exact hand-calculated decisions, reason codes, and minor-unit balances; 11/11 audit events pass SHA-256 chain & replay verification.
- **Integration & Resilience ([`reports/integration_report.json`](reports/integration_report.json)):** 30-worker concurrent revocation race yields `0` post-revocation `ALLOW`s; 20-worker duplicate approval race allows `1` and denies `19` (`ERR_APPROVAL_ALREADY_USED`); SQLite restart durability verified under `go test -race`.
- **Adversarial Evaluation ([`reports/adversarial_report.json`](reports/adversarial_report.json)):** 16/16 attack vectors blocked (including 8 delegation escalation vectors, JWT HS256/`none` downgrade, altered amount, agent self-approval, cascading revocation) plus 20/20 seeded payload mutations (`seed=20261127`), reproducible identically across runs.
- **Measured Local Microbenchmarks ([`reports/benchmark_raw.txt`](reports/benchmark_raw.txt), Go 1.27.1 on `darwin/arm64` Apple M5, synthetic in-memory SQLite):**
  - EdDSA Grant Sign + Verify: `~44.0 µs/op` (`43,952 ns/op`)
  - End-to-End Authorize (JWT verify + ACID TX + revocation check + audit chain append): `~110.8 µs/op` (`110,839 ns/op`)
  - Hash-Chained Audit Replay (100 events): `~522.5 µs/100 events` (`~5.2 µs/event`)

## Documentation

- [Architecture & Trust Boundaries](docs/architecture.md)
- [Data Contracts, Units & Error Taxonomy](docs/contracts.md)
- [ADR-0001: Stack Selection & Exact-Action Authorization](docs/adr/0001-stack-and-boundaries.md)
- [Integration Boundaries, Dependencies & Provenance](docs/integration.md)
- [Operator & Developer Runbook](docs/runbook.md)
- [Acceptance Evidence Report](reports/acceptance.md)
- [CI Validation Workflow](../../.github/workflows/agent-identity-and-authorization-platform.yml)

## Assumptions and Known Limitations

- **Mock Actions & Synthetic Keys Only:** No real financial rail integration, no live capital, no real customer data, and no HSM/KMS integration. Synthetic Ed25519 keys are used for deterministic local testing.
- **PostgreSQL Adapter Untested Against Live Daemon:** `src/store/postgres.go` and `config/schema/postgres.sql` compile cleanly (`go build ./...`, `go vet ./...`), but live PostgreSQL execution was **not run** in this offline environment (no local `psql` server available). Default SQLite ACID mode is fully tested.
- **Clock Assumption:** Default `clock_skew_seconds` is `0` for deterministic tests; distributed deployments require NTP synchronization and explicit skew configuration.
- **Production Readiness:** Any future production deployment requires independent security, operational, legal, and risk reviews, HSM-backed signing keys, mTLS/SPIFFE workload attestation, and externalized audit log replication.
