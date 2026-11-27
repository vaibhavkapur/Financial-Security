# Integration Guide and Adapter Boundaries

## 1. Reusable Interfaces in This Project

All stateful or external boundaries are exposed as small Go interfaces so downstream or neighboring projects can substitute distributed backends without touching core evaluation logic:

| Interface | Package | Local-Lab Default | Intended Distributed Adapter |
|---|---|---|---|
| `NonceStore` | `src/signing` | `MemoryNonceStore` | Redis `SET key 1 NX EX <ttl>` |
| `Limiter` | `src/ratelimit` | `TokenBucketLimiter` | Redis Lua sliding/token-bucket script |
| `CertRevocationStore` | `src/pki` | `MemoryCertRevocationStore` | PostgreSQL CRL table / OCSP responder |
| `TokenRevocationStore` | `src/oidc` | `MemoryTokenRevocationStore` | Redis TTL set or PostgreSQL `revoked_jti` table |
| `Sink` | `src/audit` | `MemorySink`, `JSONLSink`, `MultiSink` | Kafka/OTLP/PostgreSQL append-only audit sink |
| `Clock` | `src/domain` | `RealClock`, `FixedClock` | Deterministic test/replay clock injection |

> **Scope note:** External Redis and PostgreSQL servers are **not** started or tested in this offline local-lab prototype. Adapters should implement the interfaces above and run their own integration tests against a managed test container when deployed outside the offline lab.

## 2. Compatibility with Sibling `Financial-Security` Projects

The sibling projects in `Financial-Security/projects/` run as independent modules with zero direct cross-project code imports; integration happens over typed wire and file contracts:

1. **`projects/agent-identity-and-authorization-platform/` (Project 64):**
   - Can issue short-lived delegated JWTs conforming to `docs/contracts.md` (`iss`, `sub`, `aud`, `scope`, `cnf.x5t#S256`) and publish public keys via RFC 7517 JWKS compatible with `src/oidc.KeyRing`.
   - Keep integration strictly via the HTTP JWKS + JWT wire contract (independent runnable adapter), never by copying internal structs.
2. **`projects/trading-infrastructure-security-monitor/` (Project 65):**
   - Can directly ingest `reports/audit_sample.jsonl` (`domain.AuditEvent` schema v`1.0.0`) as normalized, pre-redacted authentication and authorization telemetry for anomaly correlation (`ERR_NONCE_REPLAY`, `ERR_SCOPE_INSUFFICIENT`, `ERR_MTLS_REVOKED`, `ERR_TOKEN_KEY_REVOKED`).
3. **`projects/digital-asset-custody-platform/` (Project 66):**
   - Can sit behind `src/gateway.Server` as an upstream protected service, trusting `X-Gateway-Verified-Client`, `X-Gateway-Verified-Role`, and `X-Gateway-Verified-Scopes` on an isolated internal network hop while retaining its own independent approval/signing boundary.
4. **`projects/financial-ai-red-teaming-framework/` (Project 67):**
   - Can invoke the gateway's negative-test paths (scope escalation, stolen token replay, canary secret injection) to validate agent tool-call boundaries.

## 3. Dependencies and Licensing

| Dependency | Version | License | Provenance |
|---|---|---|---|
| Go Toolchain & Standard Library | `go 1.27.1` | BSD-3-Clause | Official Go distribution |
| Third-party Go modules | None (`0` external deps) | N/A | Pure standard-library implementation |
| Reference Oracle Script (dev verification) | Python 3 stdlib (`hashlib`, `hmac`) | PSF License | Used offline to generate `data/fixtures/reference_vectors.json` |
| Synthetic Fixtures & Mock Clients | `v1.0.0` | Original / project license | 100% synthetic local-lab test identities (`cli-*`, `ACC-1001`, `SIM-AAPL`); zero real customer, production, or proprietary employer/SAAT data |
