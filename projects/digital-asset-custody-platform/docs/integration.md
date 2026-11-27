# Integration & Dependency Boundaries

## 1. Reusable Go Library Interfaces

The domain and service layers are exposed as typed Go packages under `src/pkg/` so external callers or sibling `Financial-Security` adapters can import them cleanly without copying code:

| Package | Exported Surface | Purpose |
|---|---|---|
| `src/pkg/domain` | `TransferIntent`, `PolicyConfig`, `IntentRecord`, `ReconciliationReport`, `CustodyError`, `Clock` | Versioned data contracts, canonical hashing, and stable error codes |
| `src/pkg/policy` | `LoadConfig`, `ValidateConfig`, `Engine.Evaluate` | Pure, stateless deny-by-default authorization boundary |
| `src/pkg/signer` | `ApproverKeyring`, `MockMultisigCluster`, `SignRequest`, `VerifyApprovalSignature` | Isolated approval & threshold Ed25519 signer boundary |
| `src/pkg/ledger` | `Ledger`, `StateSnapshot` | Pure double-entry accounting and intent state machine |
| `src/pkg/chain` | `MockChain`, `BundleVerifier` | Deterministic offline testnet simulator (swappable with real testnet RPC adapter) |
| `src/pkg/storage` | `SnapshotStore`, `MemoryStore`, `FileStore`, `PostgresStore` | Persistence boundary aligned with `config/schema.sql` |
| `src/pkg/engine` | `CustodyService`, `ServiceOptions` | End-to-end custody coordinator |
| `src/pkg/audit` | `Log`, `VerifyEvents`, `RedactMap` | Tamper-evident hash-chained audit trail |

## 2. Sibling Repository Adapter Boundaries (`Financial-Security`)

The sibling projects in `Financial-Security/projects/` run as independent modules with zero cross-project imports; all integration points use clean typed interfaces and wire contracts:
- `../financial-api-security-gateway/` — HTTP/mTLS ingress adapter can validate external API tokens/rate limits and map authenticated JSON requests directly into `engine.CustodyService.SubmitIntent` and `ApproveIntent`.
- `../agent-identity-and-authorization-platform/` — Identity/delegation adapter can supply verified requester/approver actor identities and short-lived policy scopes before invoking `policy.Engine.Evaluate`.
- `../trading-infrastructure-security-monitor/` — Telemetry/SIEM adapter can stream `audit.Log.Events()` and `telemetry.Counters.Snapshot()` for anomaly alerting on `ERR_INTENT_HASH_MISMATCH`, `ERR_REPLAY_DETECTED`, `SIGNER_OUTAGE`, or `REORG_DETECTED`.
- `../financial-ai-red-teaming-framework/` — Red-teaming harness can exercise approval-outage and policy-boundary scenarios against the custody approval and policy interfaces.

## 3. External Infrastructure Adapter Status

| External Integration | Interface / Artifact | Status in Prototype |
|---|---|---|
| PostgreSQL persistence | `config/schema.sql`, `src/pkg/storage/postgres.go` (`database/sql`) | Schema & adapter implemented; **live PostgreSQL execution not run** (no PostgreSQL server/driver in offline environment; fails explicitly with `ERR_STORAGE_UNAVAILABLE` if nil). |
| Hardware HSM / MPC Enclave | `signer.MockMultisigCluster` / `SignRequest` | Simulated via isolated in-process `SignerNode` structs using `crypto/ed25519`; **hardware HSM integration out of scope**. |
| Live Testnet / Mainnet RPC | `chain.MockChain` | Simulated deterministically offline; **mainnet explicitly prohibited** by policy validator. |

## 4. Dependency Licenses and Fixture Provenance

- **Runtime & cryptographic dependencies:** Go standard library only (`go 1.23+`, verified on `go1.27.1`), licensed under **BSD-3-Clause**. Zero third-party Go modules are required (`go.mod` has zero external `require` entries).
- **Fixture provenance:** All addresses (`0x1111...`, `0x2222...`, `0x3333...`, `0x9999...`), actor IDs, balances, seeds (`CUSTODY-REF-SEED-2026-0001`), and timestamps (`2026-01-15T10:00:00Z`) are 100% synthetic educational fixtures authored specifically for this prototype. No real keys, customer data, live transactions, or proprietary/employer/SAAT artifacts exist anywhere in the repository.
