# Acceptance Evidence Report — Financial API Security Gateway

**Generated:** 2026-11-27  
**Environment:** `go1.27.1`, `darwin/arm64` (Apple M5, 10 CPUs), local loopback (`127.0.0.1`), `config/gateway.json` (`1.0.0`), `config/policies.json` (`2026.11.v1`), seed `42`.

> **Measurement Distinction:** All latency, pass/fail, and leak-scan figures below are **actual measured observations** produced by running `./scripts/validate.sh` and `go test -bench` on the stated environment. Financial accounts, orders, identities, and keys are **synthetic local-lab fixtures** only.

## 1. Project-Specific Acceptance Criteria

| Acceptance Criterion | Status | Measured Evidence & Artifact Link |
|---|---|---|
| **Unauthorized requests denied by default** | **PASS** | Unmatched route (`DELETE /v1/admin/wipe`, `DELETE /v1/admin/purge`) returns `403 ERR_POLICY_DEFAULT_DENY`; missing/rogue/expired/wrong-EKU mTLS certs fail TLS 1.3 handshake; `deny_by_default: false` rejected at config load. Verified in [tests/reference_oracle_test.go](../tests/reference_oracle_test.go), [tests/integration_security_test.go](../tests/integration_security_test.go), and [test_results.json](test_results.json) (`S02`, `S07`). |
| **Replays rejected** | **PASS** | Reusing `X-Request-Nonce` within TTL returns `409 ERR_NONCE_REPLAY`; stale timestamps return `401 ERR_SIG_EXPIRED`. Verified in [tests/integration_security_test.go](../tests/integration_security_test.go) and [test_results.json](test_results.json) (`S05`, `metrics_snapshot.replay_rejections: 1`). |
| **Logs contain no secrets** | **PASS** | Canary secrets (`CANARY_API_KEY_TOP_SECRET_12345`, `CANARY_COOKIE_VALUE_67890`, `CANARY_SECRET_TOKEN_DO_NOT_LOG_987654`, raw JWTs `eyJ...`, `X-Signature`) injected across integration tests, demo, and harness; automated scan reported **`0` leaks** across all emitted JSONL events. See [audit_sample.jsonl](audit_sample.jsonl) and [test_results.json](test_results.json) (`audit_secret_leaks: 0`). |
| **Report gateway overhead** | **PASS** | Measured over 500 loopback requests + Go microbenchmark (details in Section 3 and [overhead_benchmark.json](overhead_benchmark.json)): **p50 loopback delta = `+81.20 µs`** (`65.63 µs` direct vs `146.83 µs` full mTLS+OIDC+Ed25519+policy+ratelimit+audit gateway); pure evaluator = **`52.27 µs/op`** (`3,073 B/op`, `33 allocs/op`). |
| **All required test scenarios pass (or unavailable deps marked not run)** | **PASS** | `go test -race -v ./...`: **100% PASS** (`2.376s`). Harness: **2/2** independent Python oracle vectors passed (`0` deviation), **11/11** live security scenarios passed. Unavailable external services explicitly marked in Section 4. |
| **README documents setup, demo, validation, assumptions & limitations** | **PASS** | Documented in [README.md](../README.md), [docs/runbook.md](../docs/runbook.md), and [docs/architecture.md](../docs/architecture.md). |
| **No real transactions, customer data, credentials, or proprietary artifacts** | **PASS** | All keys are ephemeral local-lab keys (`OU=LOCAL-LAB-TEST-ONLY`); all fixtures are synthetic (`cli-*`, `ACC-1001`, `SIM-AAPL`, `SIMULATED_PAPER_ONLY`). |

## 2. Test & Validation Matrix Mapping

| Test Area | Required Scenario | Test / Report Evidence | Observed Result |
|---|---|---|---|
| **Domain correctness** | Expired/forged tokens, wrong audience, wrong issuer, `alg:none`, `HS256` confusion, independent signing oracle | `TestIndependentSigningOracleVectors`, `TestDomainReferenceDecisionCases`, `TestES256TokenAndAlgorithmConfusionRejected`, [baseline_reference.json](baseline_reference.json) | **PASS** (2/2 oracle exact match, 10/10 reference cases, ES256/HS256 pass) |
| **Integration & resilience** | Replay, scope escalation, token theft (`cnf.x5t#S256`), per-route rate limit, mTLS negative certs, audit redaction | `TestIntegrationValidReplayScopeEscalationRateLimitAndRedaction`, [test_results.json](test_results.json) (`S01`–`S07`) | **PASS** (all assertions & 0 audit secret leaks) |
| **Boundary & failure behavior** | Key rotation (OIDC & client signing), JTI/cert revocation, upstream timeout (`504`) | `TestKeyRotationAndRevocation`, `TestUpstreamTimeoutFailureBehavior`, [test_results.json](test_results.json) (`S08`–`S11`) | **PASS** (`ERR_TOKEN_KEY_REVOKED`, `ERR_SIG_KEY_REVOKED`, `ERR_TOKEN_REVOKED`, `ERR_MTLS_REVOKED`, `504 ERR_UPSTREAM_TIMEOUT`) |
| **Reproducibility** | Versioned config/fixtures + fixed clock (`2026-01-15T12:00:00Z`) + fixed seed (`42`) | `TestDeterministicReproducibility` | **PASS** (byte-for-byte identical JSON outputs across independent runs) |
| **Operational review** | Missing config, invalid config (`invalid_missing_issuer.json`), `deny_by_default=false`, unsupported method (`TRACE`), oversized payload | `TestOperationalConfigValidationAndUnsupportedInputs`, `./scripts/validate.sh` | **PASS** (explicit errors, zero silent success) |

## 3. Measured Gateway Overhead Summary

Source: [overhead_benchmark.json](overhead_benchmark.json) (500 sequential pooled keep-alive requests on `127.0.0.1`, `darwin/arm64`, `go1.27.1`) and `go test -bench=BenchmarkEvaluatorFullPipeline -benchmem ./tests`.

| Series | Samples | Mean (µs) | p50 (µs) | p95 (µs) | p99 (µs) | Throughput (req/s) |
|---|---:|---:|---:|---:|---:|---:|
| Direct Upstream HTTP (baseline) | 500 | 69.99 | 65.63 | 91.63 | 111.92 | 14,273.19 |
| Full Gateway (TLS 1.3 mTLS + OIDC EdDSA + Ed25519 Sig + Nonce + Policy + RateLimit + Redacted Audit) | 500 | 156.95 | 146.83 | 211.75 | 290.29 | 5,795.96 |
| **Measured Gateway Overhead Delta** | — | **+86.96** | **+81.20** | **+120.12** | **+178.37** | — |
| Pure In-Memory `Evaluator.Evaluate` (harness) | 500 | 52.09 | 51.42 | 58.08 | 66.38 | 15,516.77 |
| Pure In-Memory `BenchmarkEvaluatorFullPipeline` (`go test -bench`) | 23,182 ops | 52.27 | — | — | — | `3,073 B/op`, `33 allocs/op` |

## 4. Explicitly Untested / Out-of-Scope Capabilities

- **External Redis / PostgreSQL Backing Stores:** **NOT RUN** (not installed/started in the offline local lab; abstracted behind `NonceStore`, `Limiter`, `CertRevocationStore`, `TokenRevocationStore`, and `AuditSink` interfaces documented in [docs/integration.md](../docs/integration.md)).
- **Production PKI / HSM / OCSP / External IdP Integration:** **OUT OF SCOPE** (local-lab prototype only; do not use for live capital, real customer data, or compliance claims).
- **Multi-Host Network Latency & TLS Session Resumption Under High Concurrency:** **NOT RUN** (benchmarks reflect single-host loopback `127.0.0.1` with pooled TLS 1.3 connections).
