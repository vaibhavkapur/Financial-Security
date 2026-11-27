# ADR 0001: Language Stack, Trust Boundaries, and Offline Verification Strategy

**Status:** Accepted  
**Date:** 2026-01-15 (prototype baseline)  
**Scope:** `projects/digital-asset-custody-platform`

## Context

The Digital Asset Custody Platform prototype must demonstrate policy-controlled custody with strict separation between identity/policy evaluation, independent approvals, isolated threshold signing, double-entry ledger accounting, and chain reconciliation. It must run deterministically and reproducibly in offline environments without real private keys, real funds, or proprietary dependencies.

## Decision

1. **Implementation language and cryptography:** Use **Go** (`go 1.23+`) with standard library cryptography (`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`) and **zero third-party runtime dependencies**.
2. **Strict in-code boundary separation:** Organize code into decoupled packages (`domain`, `policy`, `ledger`, `signer`, `chain`, `audit`, `storage`, `engine`) where `signer.SignerNode` has no reference to `ledger.Ledger` or `policy.Engine` and independently re-verifies canonical intent hashes, Ed25519 approval signatures, quorum counts, key epochs, expiry, and local replay state.
3. **Integer minor-unit accounting:** Represent all monetary quantities strictly as `int64` minor units (`gwei`, `micro_usdc`, `satoshi`) with overflow-safe comparisons, eliminating floating-point rounding drift.
4. **Persistence & chain abstraction:** Provide an atomic crash-safe `FileStore` and deterministic `MockChain` for offline testing, alongside a `config/schema.sql` relational schema and `database/sql` `PostgresStore` adapter that fails explicitly (`ERR_STORAGE_UNAVAILABLE`) when no live PostgreSQL instance is attached.

## Consequences

### Positive
- Zero external dependency supply-chain risk and trivial license compliance (Go stdlib BSD-3-Clause).
- Fast, deterministic, race-tested builds (`go test -race`) and sub-millisecond end-to-end benchmarks reproducible on any developer machine without Docker or internet access.
- Independent verification inside `SignerNode` guarantees that even a compromised orchestrator mutating a destination address after approval cannot obtain signatures.

### Trade-offs & Mitigations
- Threshold signing uses `T-of-N` independent Ed25519 signatures rather than single-signature MPC/FROST aggregation. For a prototype focused on policy/approval/signing boundary enforcement and key rotation semantics, Ed25519 is simpler, audited, and easier to verify independently.
- Live PostgreSQL integration tests are marked explicitly as **not run** in `reports/acceptance.md` until a dedicated database test harness is provisioned.
