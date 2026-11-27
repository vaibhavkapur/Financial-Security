# Acceptance & Verification Evidence Report

**Project:** Digital Asset Custody Platform (Prototype — Project 66 of 67)  
**Environment Measured:** `go1.27.1`, `darwin/arm64` (10 CPUs), offline mock testnet  
**Policy Configuration:** `config/default-policy.json` (`policy_version: policy-v1.0.0`, `policy_digest: 5a78b40524c847b93d7c05322249569be4f8b46ea6fff8dff519bab4fab8e77c`)  
**Raw Machine-Readable Artifacts:**
- `reports/baseline_reference.json`
- `reports/scenario_results.json`
- `reports/benchmark_results.json`

> **Measurement Distinction:** All test pass results, cryptographic digests, reconciliation checksums, and benchmark timings below are **actual measured observations** from executing `./scripts/validate.sh` on synthetic offline fixtures. No real keys, live testnet/mainnet networks, or customer funds were used.

---

## 1. Project-Specific Acceptance Criteria (Plan Section 5)

| # | Acceptance Criterion | Status | Automated Verification & Measured Evidence |
|---|---|---|---|
| 1 | **No unauthorized signing** | **PASS** | Verified in `TestTamperedDestinationRejected`, `TestMissingQuorumAndUnauthorizedApproval`, `TestReplayProtection`, `TestKeyRotationWithPendingIntent`, and `reports/scenario_results.json`. Across all adversarial tests (tampered destination/amount, missing quorum, self-approval, forged Ed25519 signature, duplicate approver, stale epoch, replay), `signatures_issued == 0` for every unauthorized request and isolated `SignerNode` fails closed. |
| 2 | **Intent hash matches approved payload** | **PASS** | Verified in `TestReferenceFixtureMatchesIndependentOracle` and `TestTamperedDestinationRejected`. Reference fixture hash `77fed00728a365eb0a7554623e56feee1fd5cc6a90fc2e502096f2a505bff7ef` matches the independent Python SHA-256 oracle (`oracle_matched: true` in `reports/baseline_reference.json`). Mutating destination or amount triggers `ERR_INTENT_HASH_MISMATCH` via constant-time compare. |
| 3 | **All balances and pending transfers reconcile** | **PASS** | Verified in every test and scenario via `CustodyService.Reconcile()`. Baseline run (`reports/baseline_reference.json`): `vault_confirmed_balance = 8,500,000,000`, `onchain_confirmed_balance = 8,500,000,000`, `balance_delta = 0`, `reserved_delta = 0`, `reconciled = true`, `audit_chain_valid = true`, checksum `f62bab1dc2b28ebe7c716c349cc29a2400d3707caef3cb2ae192cb6052fd04ed`. Mid-reorg, post-reorg, dropped-tx reorg, signer outage recovery, key rotation, and cold restart all reconcile with zero delta. |
| 4 | **All required test scenarios pass (unavailable deps marked not run)** | **PASS** | All 13 top-level Go test functions (including subtests) pass under `go test -race -count=1 -v ./...` and all 6 scenario suite checks pass (`all_passed: true` in `reports/scenario_results.json`). Unavailable dependencies (live PostgreSQL, hardware HSM, live testnet RPC) are explicitly marked **NOT RUN** in Section 4 below. |
| 5 | **README documents setup, demo, validation, assumptions, and limitations** | **PASS** | Documented in `README.md`, `docs/runbook.md`, `docs/architecture.md`, `docs/contracts.md`, and `docs/integration.md`; measured results explicitly separated from synthetic fixtures and out-of-scope production targets. |
| 6 | **No real transactions, customer data, credentials, or proprietary/SAAT artifacts** | **PASS** | Verified by `TestAuditRedactionAndTamperDetection`, `TestOperationalRestartAndRerunDurability` (verifying master seed never appears in persisted snapshot), and automated secret-pattern check in `scripts/validate.sh`. |

---

## 2. Test & Validation Matrix Mapping (Plan Section 4)

| Test Area | Required Scenario | Test Function(s) | Measured Result / Evidence |
|---|---|---|---|
| **Domain correctness** | Tampered destination and missing quorum | `TestTamperedDestinationRejected`, `TestMissingQuorumAndUnauthorizedApproval`, `TestInvalidInputsFixture`, `TestDailyLimitEnforcement` | **PASS** — Isolated signer returned `ERR_INTENT_HASH_MISMATCH` (tampered destination & amount) and `ERR_INSUFFICIENT_APPROVALS` (1/2 quorum, forged cert, 2/3 high-value); `signatures_issued = 0`. See `scenario-tampered-destination` and `scenario-missing-quorum` in `reports/scenario_results.json`. |
| **Integration and resilience** | Replay, signer outage, and reorg | `TestReplayProtection`, `TestSignerOutageAndRecovery`, `TestChainReorgRequeueAndDrop` | **PASS** — Replay blocked across ledger (`ERR_REPLAY_DETECTED`), isolated signer (`ERR_REPLAY_DETECTED`), and mock chain (`replays_blocked = 3`). Signer outage: 1/3 offline succeeded (`0x8236802f...`), 2/3 offline failed closed (`ERR_SIGNER_QUORUM_UNAVAILABLE`), recovery succeeded (`0x6f6d644f...`). Chain reorg: 1-block reorg reverted provisional settlement (`status_mid_reorg = BROADCAST`), reconciled mid-reorg, and re-confirmed on canonical fork (`0xec820056...`); dropped-tx subtest released reserved balance cleanly. |
| **Boundary and failure behavior** | Key rotation with pending intent | `TestKeyRotationWithPendingIntent` | **PASS** — Rotating epoch 1 -> 2 invalidated `intent-rot-pending-01` (`status = INVALIDATED_KEY_ROTATION`), released reserved balance (`reserved_after_rotation = 0`), rejected stale-epoch signing at both engine and isolated signer (`ERR_KEY_EPOCH_MISMATCH`), settled already-broadcast epoch-1 tx, and confirmed replacement epoch-2 tx (`0x5f431928...`). |
| **Reproducibility** | Same versioned inputs/config and fixed seed | `TestDeterministicReproducibility`, `TestReferenceFixtureMatchesIndependentOracle` | **PASS** — Two independent runs produced byte-for-byte identical JSON outputs (intent hash, tx hash, block hash, reconciliation checksum, counters). Zero tolerance drift (exact deterministic match). |
| **Operational review** | Missing config, unsupported inputs, restart/rerun | `TestOperationalMissingAndInvalidConfig`, `TestOperationalRestartAndRerunDurability`, `TestAuditRedactionAndTamperDetection` | **PASS** — Missing config -> `ERR_MISSING_CONFIG`; bad JSON -> `ERR_INVALID_CONFIG`; mainnet config -> `ERR_UNSUPPORTED_NETWORK`; nil Postgres handle -> `ERR_STORAGE_UNAVAILABLE`; cold restart from `FileStore` restored epoch 2, balances, audit hash chain, and replay caches with zero seed leakage. |

---

## 3. Measured Benchmarks (`reports/benchmark_results.json`)

Measured on `go1.27.1` (`Darwin` / `arm64`, 10 CPUs):

| Benchmark | Iterations | Latency (`ns/op`) | Allocations (`B/op`) | Allocs (`allocs/op`) |
|---|---:|---:|---:|---:|
| `BenchmarkIntentHashAndPolicyEvaluate-10` | 756,456 | 1,576.0 ns (~1.58 µs) | 1,417 B | 14 |
| `BenchmarkEndToEndCustodyTransfer-10` | 2,857 | 424,552.0 ns (~0.42 ms) | 114,824 B | 1,066 |

*(End-to-end benchmark includes full deposit, intent submission, policy evaluation, 2 Ed25519 approvals, 2-of-3 isolated Ed25519 multisig signing, mock chain broadcast, 2-block mining, and reconciliation.)*

---

## 4. Explicitly Untested / Out-of-Scope Capabilities

| Capability | Status | Rationale |
|---|---|---|
| Live PostgreSQL persistence (`config/schema.sql`, `src/pkg/storage/postgres.go`) | **NOT RUN** | No PostgreSQL server or third-party Go SQL driver (`pgx`/`lib/pq`) is installed in the offline test environment. Schema and `database/sql` adapter are implemented and nil-handle behavior is verified (`ERR_STORAGE_UNAVAILABLE`). |
| Hardware HSM / FIPS 140-3 enclave / MPC-TSS (GG20/FROST) | **OUT OF SCOPE** | Simulated via isolated in-process `SignerNode` structs using standard library `crypto/ed25519` and synthetic test seeds. |
| Live public testnet or mainnet RPC execution | **OUT OF SCOPE / PROHIBITED** | Mainnet networks are explicitly blocked in `policy.ValidateConfig` and `policy.Engine.Evaluate`. |
| Solidity smart-contract multisig deployment | **OPTIONAL / NOT IMPLEMENTED** | Plan lists Solidity as optional; pure Go Ed25519 custody prototype selected per ADR 0001. |
