# ADR-0001: Stack Selection, Trust Boundaries, and Exact-Action Authorization Model

- **Status:** Accepted
- **Date:** 2026-11-27
- **Project:** Agent Identity and Authorization Platform (AIAP)

## Context

Simulated financial agents executing delegated actions (mock payments, trades, portfolio rebalances, and account reads) introduce high-impact authorization risks:

1. **Ambient or over-broad authority** if agents reuse static credentials.
2. **Delegation escalation** if an agent re-delegates broader scopes, higher spending limits, longer TTLs, or relaxed approval thresholds to a sub-agent.
3. **Time-of-check to time-of-use (TOCTOU) races** between grant revocation and concurrent action execution, or between concurrent submissions reusing a single approval record.
4. **Payload tampering** if an approval is bound only to an action type rather than the exact canonicalized action payload (amount, currency, counterparty, resource).

## Decision

### 1. Language and Established Crypto Library
We select **Go** (`go1.24+`) with:
- **`github.com/golang-jwt/jwt/v5` (`v5.3.1`)** and Go's standard `crypto/ed25519` for **RFC 7519 / RFC 8037 EdDSA (Ed25519)** signed short-lived grants.
- Strict algorithm pinning (`jwt.WithValidMethods([]string{"EdDSA"})`) to prevent `alg: none` and HMAC key-confusion downgrade attacks.
- No custom cryptographic primitives; SHA-256 (`crypto/sha256`) is used strictly for canonical payload digests and audit hash chaining.

### 2. Three Strict Component Boundaries
1. **Identity & Policy (`src/domain`, `src/crypto`):** Pure, I/O-free domain validation, monotonic delegation attenuation checks, deterministic canonical JSON hashing, and short-lived EdDSA grant issuance/verification.
2. **Enforcement & State (`src/enforcer`, `src/store`):** Deny-by-default Policy Enforcement Point (PEP) + Policy Decision Point (PDP) executing revocation checks, chain-wide cumulative spending updates, and single-use approval consumption within a single ACID transaction.
3. **Audit & Evaluation (`src/audit`):** Redacted telemetry, SHA-256 hash-chained append-only audit log, deterministic audit replay verifier, and seeded adversarial delegation evaluator.

### 3. Dual Storage Architecture (SQLite Default + PostgreSQL Adapter)
- **SQLite (`modernc.org/sqlite`)** provides a zero-external-daemon, deterministic, ACID-compliant store using `BEGIN IMMEDIATE` transactions so revocation races and duplicate approval races are linearly serialized in local tests and CI.
- **PostgreSQL (`github.com/jackc/pgx/v5`)** is provided as a full runnable adapter with matching DDL (`config/schema/postgres.sql`) using `SERIALIZABLE` / row-level locking semantics. In offline environments without a live PostgreSQL instance, compilation is verified while live PostgreSQL execution is explicitly marked as not run.

### 4. Integer Minor-Unit Monetary Accounting
All monetary amounts and spending caps are represented as non-negative 64-bit integers (`amount_minor`, e.g., USD cents) paired with an explicit ISO-4217 currency code. Floating-point numbers are disallowed in financial contracts to eliminate rounding drift.

### 5. Exact-Action Cryptographic Binding
Approvals are signed by the delegator's Ed25519 key over the canonical `action_digest = SHA-256("aiap.action.v1:" || canonical_json(action))` plus `approval_id`, `grant_id`, `actor_id`, `expires_at_utc`, and `nonce`. Any alteration to amount, currency, counterparty, resource, or action type invalidates the digest immediately.

## Consequences

- **Positive:** Fully deterministic offline tests and benchmarks; race-safe revocation and single-use approval guarantees; zero floating-point ambiguity; clean separation between pure domain logic and persistence/I/O.
- **Trade-offs:** Strict `BEGIN IMMEDIATE` serialization trades peak cross-grant write concurrency for simple linearizability in SQLite (PostgreSQL row locks narrow contention to per-grant/root-grant rows). Clock skew defaults to `0s` for deterministic testing and can be explicitly tuned via config.
- **Limitations:** Prototype scope only; mock keys and simulated actions. Production adoption requires HSM/KMS key custody, mTLS/SPIFFE workload identity attestation, distributed key rotation, and independent security review.
