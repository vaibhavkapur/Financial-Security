# Financial API Security Gateway

> **Project 63 of 67** (`Financial-Security`) — Independently developed educational/research local-lab prototype. Offline synthetic simulation only; **not** for production use, live capital, real customer data, or compliance claims.

Protects simulated financial APIs with explicit identity, authorization, request-integrity, and redacted audit boundaries:

- **Test CA & TLS 1.3 mTLS** (`src/pki`) with live certificate revocation (enforced both at TLS handshake and per-request on keep-alive connections) and RFC 8705 `x5t#S256` thumbprint binding.
- **Mock OAuth2/OIDC JWT & JWKS** (`src/oidc`) with `EdDSA`/`ES256` allowlisting, strict `iss`/`aud`/`exp`/`nbf` checks, `alg:none` and `HS256` downgrade rejection, zero-downtime key rotation, and `jti` revocation.
- **Canonical Request Signing & Replay Prevention** (`src/signing`) over method, path, sorted query, RFC 3339 UTC timestamp, nonce, `kid`, and SHA-256 body digest (`Ed25519` and `HMAC-SHA256`), verified against an independent Python reference oracle.
- **Deny-by-Default Per-Resource Policy & Token-Bucket Rate Limiting** (`src/policy`, `src/ratelimit`) enforcing role allowlists, required scopes, client scope ceilings, payload bounds, and `429 Retry-After`.
- **Redacted Structured Audit Logging & Diagnostics** (`src/audit`) guaranteeing zero secret leakage in JSONL logs, plus strict upstream timeout enforcement (`504 ERR_UPSTREAM_TIMEOUT`).

## Quickstart

From `projects/financial-api-security-gateway/`:

```bash
# 1. Build binaries and validate configuration
./scripts/setup.sh

# 2. Run the self-contained local-lab end-to-end demo
./scripts/demo.sh

# 3. Run full validation (go vet, -race test suite, demo, negative/rotation harness, secret-leak scan)
./scripts/validate.sh

# 4. Run microbenchmarks and live loopback overhead benchmark
./scripts/benchmark.sh
```

## Example Demo Output

```text
=== Financial API Security Gateway — Local-Lab Demo ===
[1] Valid mTLS+OIDC+Signed GET balance      -> HTTP 200 | {"account_id":"ACC-1001","balance":125000.5,"currency":"USD","mode":"SIMULATED_PAPER_ONLY",...}
[2] Valid mTLS+OIDC+Signed POST paper order -> HTTP 200 | {"order_id":"SIM-ORD-00001","status":"ACCEPTED_PAPER","symbol":"SIM-AAPL",...}
[3] Replayed nonce rejected                 -> HTTP 409 | {"error_code":"ERR_NONCE_REPLAY","message":"replayed request nonce rejected",...}
[4] Scope/role escalation denied            -> HTTP 403 | {"error_code":"ERR_ROLE_FORBIDDEN",...}
[5] Unknown route denied by default         -> HTTP 403 | {"error_code":"ERR_POLICY_DEFAULT_DENY",...}
[6] OIDC rotation (new kid=200, revoked old kid=401) | {"error_code":"ERR_TOKEN_KEY_REVOKED",...}
[7] Upstream timeout handled                -> HTTP 504 | {"error_code":"ERR_UPSTREAM_TIMEOUT",...}

Audit log written to: reports/audit_sample.jsonl (8 events, 0 secrets leaked)
```

## Measured Gateway Overhead (Actual Observation)

Measured on `darwin/arm64` (Apple M5, Go `1.27.1`, 500 pooled keep-alive requests on `127.0.0.1`; full raw output in [`reports/overhead_benchmark.json`](reports/overhead_benchmark.json)):

- **Direct Upstream HTTP (baseline):** p50 `65.63 µs` (mean `69.99 µs`, p95 `91.63 µs`, `14,273 req/s`)
- **Full Security Gateway (TLS 1.3 mTLS + OIDC EdDSA + Ed25519 Request Sig + Nonce + Policy + RateLimit + Redacted Audit):** p50 `146.83 µs` (mean `156.95 µs`, p95 `211.75 µs`, `5,796 req/s`)
- **Measured Gateway Overhead Delta:** **p50 `+81.20 µs`** (mean `+86.96 µs`, p95 `+120.12 µs`, p99 `+178.37 µs`)
- **Pure In-Memory Security Evaluator (`go test -bench`):** **`52.27 µs/op`**, `3,073 B/op`, `33 allocs/op`

## Repository Layout & Evidence Links

| Path | Description |
|---|---|
| [`src/`](src/) | Isolated domain, PKI/mTLS, OIDC, signing/replay, policy, rate-limit, audit, gateway, mock API, and CLI binaries |
| [`tests/`](tests/) | Independent oracle, live mTLS integration, rotation/revocation/failure, reproducibility, and benchmark tests |
| [`config/`](config/) | Versioned `gateway.json`, `policies.json`, `clients.json`, and negative config fixture |
| [`data/fixtures/reference_vectors.json`](data/fixtures/reference_vectors.json) | Deterministic Python-verified signing oracle vectors & decision reference cases |
| [`docs/architecture.md`](docs/architecture.md) | Component/sequence Mermaid diagrams, boundary separation, invariants & trade-offs |
| [`docs/adr/0001-architecture-and-stack.md`](docs/adr/0001-architecture-and-stack.md) | Architecture Decision Record for Go stdlib stack & boundary design |
| [`docs/contracts.md`](docs/contracts.md) | Input/output schemas, units, UTC timestamp semantics, wire signing spec & error codes |
| [`docs/integration.md`](docs/integration.md) | Pluggable store interfaces, sibling project compatibility, licenses & fixture provenance |
| [`docs/runbook.md`](docs/runbook.md) | Setup, demo, validation, key rotation, revocation & operational recovery steps |
| [`reports/acceptance.md`](reports/acceptance.md) | Full acceptance criteria & test matrix mapped to measured evidence |
| [`reports/`](reports/) | Raw machine-readable outputs: `baseline_reference.json`, `test_results.json`, `overhead_benchmark.json`, `audit_sample.jsonl` |
| [`../../.github/workflows/financial-api-security-gateway.yml`](../../.github/workflows/financial-api-security-gateway.yml) | Automated CI validation workflow |

## Assumptions, Provenance & Known Limitations

- **Zero External Dependencies:** Built solely on the Go `1.27` standard library (BSD-3-Clause); reference signing vectors were cross-checked offline using Python 3's standard `hashlib` and `hmac` modules.
- **Synthetic Fixtures Only:** No real transactions, customer records, production credentials, or proprietary employer/SAAT artifacts exist anywhere in source, fixtures, logs, or reports.
- **Untested / Out-of-Scope Capabilities:** External PostgreSQL and Redis backends are abstracted behind Go interfaces (`NonceStore`, `Limiter`, `CertRevocationStore`, `TokenRevocationStore`, `AuditSink`) and are **not run** in the local offline lab. Benchmarks measure single-host loopback latency with pooled TLS 1.3 connections, not multi-region WAN or production HSM/KMS latency. Any production adoption requires independent security, operational, legal, and risk review.
