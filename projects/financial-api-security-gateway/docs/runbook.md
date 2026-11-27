# Operator & Developer Runbook

## 1. Prerequisites

- Go `1.27+` (`go version`)
- macOS or Linux shell with local loopback (`127.0.0.1`) enabled
- No Docker, Redis, PostgreSQL, or internet access required for local-lab execution

## 2. Quickstart Commands

All commands are run from `projects/financial-api-security-gateway/`:

```bash
# 1. Build binaries and validate configuration
./scripts/setup.sh

# 2. Run the self-contained local-lab end-to-end demo
./scripts/demo.sh

# 3. Run the complete validation suite (vet, race tests, demo, harness, secret-leak check)
./scripts/validate.sh

# 4. Run microbenchmarks and live loopback gateway overhead benchmark
./scripts/benchmark.sh
```

Or via `Makefile`:

```bash
make build
make test
make demo
make validate
make bench
```

## 3. Operational Procedures

### 3.1 Validating Configuration Before Startup

```bash
./bin/gateway --validate-config --config-dir config
```

- Exits `0` with schema/policy summary if valid.
- Exits `1` with explicit diagnostics if required fields are missing (e.g., `oidc.issuer`), URLs/timeouts are invalid, or `deny_by_default` is disabled.

### 3.2 Live Key Rotation (Zero-Downtime Overlap)

1. Generate and promote a new active OIDC key in `oidc.KeyRing` via `RotateToNewEd25519Key(newKID, now)`.
2. Existing non-revoked keys remain in `PublicJWKS()` and continue verifying in-flight tokens during the overlap grace window (at least `max_token_ttl + max_clock_skew_seconds`).
3. Once all callers hold tokens minted with `newKID`, call `RevokeKey(oldKID, now)`. Any residual token using `oldKID` immediately fails with `401 ERR_TOKEN_KEY_REVOKED`.
4. For per-client request-signing keys, register the new key with `signing.KeyStore.AddEd25519Key(newKeyID, clientID, newPub)`, switch the client, then call `RevokeKey(oldKeyID)` (`401 ERR_SIG_KEY_REVOKED`).

### 3.3 Emergency Credential Revocation

- **Compromised Client Certificate:** Call `CertRevocationStore.Revoke(serialHex, reason)`. Both fresh TLS 1.3 handshakes and existing keep-alive HTTP connections are rejected immediately (`ERR_MTLS_REVOKED`).
- **Compromised Access Token:** Call `TokenRevocationStore.RevokeJTI(jti, expiresAt)`. Immediately returns `401 ERR_TOKEN_REVOKED`.
- **Compromised Client Identity:** Call `PolicyEngine.RevokeClient(clientID)` or update `config/clients.json` `status: "revoked"`. Immediately returns `403 ERR_CLIENT_REVOKED`.

## 4. Diagnostics & Recovery

| Symptom / Error Code | Root Cause | Recovery Step |
|---|---|---|
| `CONFIGURATION ERROR: ... oidc.issuer is required` | Missing or malformed config file | Fix `config/gateway.json` and re-run `./bin/gateway --validate-config`. |
| `401 ERR_SIG_EXPIRED` or `ERR_SIG_FUTURE` | Client/gateway clock drift exceeds window | Sync NTP / check UTC RFC 3339 formatting on `X-Request-Timestamp`. |
| `409 ERR_NONCE_REPLAY` | Client reused `X-Request-Nonce` on retry | Generate a fresh cryptographic nonce per HTTP attempt; never reuse nonces across retries. |
| `401 ERR_CERT_TOKEN_MISMATCH` | Token `cnf.x5t#S256` differs from mTLS leaf cert | Re-mint token bound to the active client certificate after cert rotation. |
| `429 ERR_RATE_LIMITED` | Client exceeded per-route burst/RPS | Honor `Retry-After` response header; inspect `rate_limit_hits` in metrics snapshot. |
| `504 ERR_UPSTREAM_TIMEOUT` | Upstream financial service exceeded `upstream_timeout_ms` | Inspect upstream health and `upstream_timeouts` counter; verify timeout budget in `config/gateway.json`. |
| Audit secret-leak check fails | Unredacted sensitive header or inline pattern | Add custom header/key to `config/gateway.json` under `audit.redact_headers` / `audit.redact_json_keys` and re-run `./scripts/validate.sh`. |
