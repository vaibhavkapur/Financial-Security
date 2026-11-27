# Data Contracts and Protocol Specification

**Schema Version:** `1.0.0`  
**Policy Version:** `2026.11.v1`

## 1. Units and Timestamp Semantics

| Field / Concept | Unit / Format | Semantics |
|---|---|---|
| HTTP Request Timestamp (`X-Request-Timestamp`) | RFC 3339 UTC string (e.g., `2026-01-15T12:00:00Z`) | Rejected if older than `max_request_age_seconds` or ahead by more than `max_future_skew_seconds` relative to gateway clock. |
| JWT Temporal Claims (`iat`, `nbf`, `exp`) | Unix epoch seconds (int64, UTC) | Checked with `+/- max_clock_skew_seconds` tolerance (`now <= exp + skew` and `now + skew >= nbf`). |
| Timeouts (`upstream_timeout_ms`) | Milliseconds (int > 0) | Hard deadline enforced on upstream proxy calls; exceeding returns `504 ERR_UPSTREAM_TIMEOUT`. |
| Latency (`latency_us`) | Microseconds (int64) | End-to-end gateway handling time recorded in `AuditEvent`. |
| Rate Limits (`rate_limit_rps`, `rate_limit_burst`) | Requests/second (float64 > 0), tokens (int > 0) | Token-bucket refill rate and burst capacity per `(client_id, policy_rule_id)`. |
| Payload Size (`max_body_bytes`) | Bytes (int64 >= 0) | Enforced globally (`audit.max_body_bytes`) and per policy rule (`rules[].max_body_bytes`). |

## 2. Identifiers

- **`request_id`:** Client-supplied `X-Request-ID` or gateway-generated `req-000001` monotonic identifier echoed in response headers, error payloads, upstream requests, and audit events.
- **`event_id`:** Gateway-assigned stable audit event ID (`aud-000001`).
- **`client_id`:** Canonical synthetic client identifier (`cli-ledger-reader`, `cli-order-router`, `cli-risk-auditor`, `cli-revoked-bot`). Must match both mTLS certificate `CN` and JWT `sub`.
- **`spiffe_id`:** URI SAN embedded in client certificates (`spiffe://finsec.local/clients/<client_id>`).
- **`cert_thumbprint`:** RFC 8705 `x5t#S256` — unpadded base64url(SHA-256(DER leaf cert)).
- **`jti`:** Unique JWT identifier used for audit correlation and individual token revocation.

## 3. Signed Request Wire Contract

Clients calling the gateway MUST present:

1. **TLS 1.3 mTLS Client Certificate** signed by the configured Test CA with `ExtKeyUsageClientAuth`.
2. **OIDC Bearer JWT** in `Authorization: Bearer <jwt>` signed with `EdDSA` or `ES256`, containing `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, `scope`, and `cnf.x5t#S256`.
3. **Request Integrity Headers:**
   - `X-Signature-Alg`: `Ed25519` or `HMAC-SHA256`
   - `X-Key-ID`: Registered signing key ID owned by `client_id`
   - `X-Request-Timestamp`: RFC 3339 UTC timestamp
   - `X-Request-Nonce`: Unique per-client nonce string
   - `X-Signature`: Unpadded base64url signature over the canonical string:

```text
v1
<UPPERCASE_METHOD>
<PATH>
<SORTED_URL_ENCODED_QUERY>
<X-REQUEST-TIMESTAMP>
<X-REQUEST-NONCE>
<X-KEY-ID>
<LOWERCASE_HEX_SHA256(RAW_BODY)>
```

## 4. Configuration Contracts

- **`config/gateway.json`:** Root gateway config (`schema_version`, `listen_addr`, `upstream_url`, `upstream_timeout_ms`, `deny_by_default: true`, `require_mtls`, `require_cert_bound_token`, `oidc`, `signing`, `rate_limit`, `audit`).
- **`config/policies.json`:** Deny-by-default authorization rules (`default_effect: "deny"`, list of `rules` with `id`, `method`, `path_pattern`, `required_scopes`, `allowed_roles`, `require_mtls`, `require_signature`, `rate_limit_rps`, `rate_limit_burst`, `max_body_bytes`).
- **`config/clients.json`:** Registered client identities (`client_id`, `role`, `spiffe_id`, `allowed_scopes`, `status` in `{"active","revoked"}`).

## 5. Error Response Contract

All gateway denials and upstream failures return `application/json`:

```json
{
  "schema_version": "1.0.0",
  "request_id": "req-000003",
  "error_code": "ERR_NONCE_REPLAY",
  "message": "replayed request nonce rejected",
  "timestamp": "2026-01-15T12:00:00Z"
}
```

### Canonical Error Codes

| Error Code | HTTP Status | Meaning |
|---|---|---|
| `ERR_METHOD_UNSUPPORTED` | `405` | HTTP method outside `{GET, POST, PUT, PATCH, DELETE}` |
| `ERR_BODY_TOO_LARGE` | `413` | Payload exceeds global or per-rule `max_body_bytes` |
| `ERR_POLICY_DEFAULT_DENY` | `403` | No policy matches `(method, path)` |
| `ERR_MTLS_REQUIRED` | `401` | Missing verified client certificate |
| `ERR_MTLS_REVOKED` | `401` | Client certificate serial number is revoked |
| `ERR_TOKEN_MISSING` / `ERR_TOKEN_MALFORMED` | `401` | Missing or structurally invalid Bearer JWT |
| `ERR_TOKEN_ALG_REJECTED` | `401` | Algorithm not in allowlist (`alg:none`, `HS256`, mismatch) |
| `ERR_TOKEN_KEY_UNKNOWN` / `ERR_TOKEN_KEY_REVOKED` | `401` | Unknown or revoked JWKS `kid` |
| `ERR_TOKEN_SIG_INVALID` | `401` | Cryptographic JWT signature verification failed |
| `ERR_TOKEN_ISSUER_MISMATCH` / `ERR_TOKEN_AUDIENCE_MISMATCH` | `401` | `iss` or `aud` claim mismatch |
| `ERR_TOKEN_EXPIRED` / `ERR_TOKEN_NOT_YET_VALID` | `401` | `exp`/`nbf` outside clock skew tolerance |
| `ERR_TOKEN_REVOKED` | `401` | Token `jti` explicitly revoked |
| `ERR_CERT_TOKEN_MISMATCH` | `401` | `cnf.x5t#S256` does not match mTLS leaf certificate |
| `ERR_SUBJECT_CERT_MISMATCH` | `403` | JWT `sub` differs from mTLS certificate `CN` |
| `ERR_CLIENT_UNKNOWN` / `ERR_CLIENT_REVOKED` | `403` | Unregistered or revoked client identity |
| `ERR_SIG_MISSING` / `ERR_SIG_ALG_REJECTED` / `ERR_SIG_KEY_UNKNOWN` / `ERR_SIG_KEY_REVOKED` / `ERR_SIG_TIMESTAMP_INVALID` / `ERR_SIG_EXPIRED` / `ERR_SIG_FUTURE` / `ERR_SIG_INVALID` | `401` | Request signature or timestamp freshness failure |
| `ERR_NONCE_MISSING` | `401` | Missing `X-Request-Nonce` |
| `ERR_NONCE_REPLAY` | `409` | Nonce already consumed within TTL window |
| `ERR_ROLE_FORBIDDEN` / `ERR_SCOPE_INSUFFICIENT` / `ERR_SCOPE_NOT_GRANTED_TO_CLIENT` | `403` | Role or per-resource scope authorization denied |
| `ERR_RATE_LIMITED` | `429` | Per-client/route token bucket exhausted (`Retry-After` header set) |
| `ERR_UPSTREAM_TIMEOUT` | `504` | Simulated financial upstream exceeded `upstream_timeout_ms` |
| `ERR_UPSTREAM_UNAVAILABLE` | `502` | Upstream connection failed |

## 6. Redacted Audit Event Output Contract (`AuditEvent`)

Emitted as one JSON object per line (`JSONL`):
`event_id`, `schema_version`, `timestamp`, `request_id`, `client_id`, `client_role`, `cert_thumbprint`, `cert_serial_hex`, `token_jti`, `method`, `path`, `policy_rule_id`, `decision`, `reason_code`, `http_status`, `latency_us`, `redacted_headers`, `redacted_count`, `message`.

## 7. Valid, Invalid, and Boundary Fixtures

- `data/fixtures/reference_vectors.json` — Independent Python-computed canonical signing oracle vectors (`sig-vec-get-balance`, `sig-vec-post-order`) and 10 valid/invalid/boundary decision cases (`ref-valid-balance`, `ref-valid-order`, `ref-expired-token`, `ref-forged-token`, `ref-wrong-audience`, `ref-wrong-issuer`, `ref-alg-none`, `ref-scope-escalation`, `ref-unmatched-route-default-deny`, `ref-revoked-client`).
- `config/invalid_missing_issuer.json` — Operational negative configuration fixture.
