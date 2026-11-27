# ADR-0001: Language Stack, Cryptographic Primitives, and Boundary Isolation

- **Status:** Accepted
- **Date:** 2026-11-27
- **Project:** Financial API Security Gateway (Project 63 of 67)

## Context

The Financial API Security Gateway prototype must demonstrate mTLS, OIDC token validation (`iss`/`aud`/key rotation/revocation), canonical request signing with replay prevention, deny-by-default per-resource authorization, rate limiting, redacted audit logging, and measurable gateway overhead in an offline local lab.

## Decision

1. **Use Go (`go 1.27`) with the Go Standard Library (`zero third-party dependencies`):**
   - Go's standard library provides audited, established cryptographic and networking primitives (`crypto/tls` TLS 1.3, `crypto/x509`, `crypto/ed25519`, `crypto/ecdsa`, `crypto/hmac`, `crypto/sha256`, `net/http/httputil.ReverseProxy`).
   - Zero external dependencies guarantee clean offline builds, trivial license auditing (BSD-3-Clause Go stdlib), and exact reproducibility across developer environments and CI.
2. **Isolate the Security Evaluator from Transport I/O:**
   - Place all decision logic inside `gateway.Evaluator.Evaluate(domain.RequestEnvelope)` driven by an injectable `domain.Clock`.
   - This allows deterministic unit tests and cross-language reference oracle verification without network jitter, while `gateway.Server` wires the exact same evaluator onto live TLS 1.3 mTLS sockets.
3. **Abstract Stateful Stores Behind Go Interfaces:**
   - Define `signing.NonceStore`, `ratelimit.Limiter`, `pki.CertRevocationStore`, `oidc.TokenRevocationStore`, and `audit.Sink`.
   - Ship deterministic in-memory (and JSONL file) implementations for the local lab and document PostgreSQL/Redis adapter contracts in `docs/integration.md`.
4. **Use an Independent Python Reference Oracle for Canonical Signing:**
   - Generate reference SHA-256 body digests, canonical strings, and HMAC-SHA256 signatures independently with Python 3's `hashlib` and `hmac` modules and store them in `data/fixtures/reference_vectors.json` to detect encoding or canonicalization bugs.

## Consequences

- **Positive:** Fast builds (`<1s`), race-detector coverage (`go test -race`), zero external daemon setup, sub-millisecond gateway overhead (`~81 µs` p50 loopback delta), and deterministic regression tests.
- **Negative / Limitations:** Multi-instance horizontal scaling of nonce replay windows, rate-limit buckets, and revocation lists requires implementing the Redis/PostgreSQL adapters (marked explicitly as not run in the local offline lab).
