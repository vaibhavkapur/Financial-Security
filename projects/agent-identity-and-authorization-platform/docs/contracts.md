# Data Contracts and Schemas

**Version:** `1.0.0`  
**Policy Engine Version:** `aiap-policy-v1.0.0`  
**Scope:** Simulated financial agent identities, delegation grants, spending limits, action payloads, approval records, and authorization decision outputs.

## 1. Global Conventions

- **Units:** All monetary values use signed/non-negative 64-bit integer **minor units** (`int64`, field suffix `_minor`), e.g., `10000` with currency `"USD"` represents `$100.00`. Floating-point representations are forbidden.
- **Currencies:** Uppercase 3-character ISO-4217 codes from the configured allowlist (`USD`, `EUR`, `GBP`).
- **Timestamps:** RFC 3339 / ISO-8601 UTC strings with second precision (`YYYY-MM-DDTHH:MM:SSZ`), evaluated against an injectable clock (`Clock`) for deterministic testing and replay.
- **Identifiers:**
  - `principal_id`: `[a-z0-9][a-z0-9._-]{2,63}` (e.g., `delegator.treasury.alice`, `agent.rebalancer.01`)
  - `grant_id`, `approval_id`, `decision_id`, `revocation_id`: opaque unique identifiers (UUIDv4 in live mode; deterministic prefixed IDs in fixture/seeded mode).
  - `tenant_id`: non-empty tenant isolation namespace (e.g., `mock-tenant-alpha`). Cross-tenant delegation or action execution is always denied.
- **Deny-by-default:** Any missing field, unrecognized `action_type`, unlisted `audience`, unsupported currency, or unknown `alg` fails closed with an explicit error/reason code.

---

## 2. Canonical Input Contracts

### 2.1 Principal (`Principal`)
Represents a delegator (human or service) or an automated agent.

| Field | Type | Constraints | Description |
|---|---|---|---|
| `principal_id` | string | Required, pattern | Unique actor or delegator ID |
| `principal_type` | enum | `human_delegator` \| `service_delegator` \| `agent` | Identity role |
| `display_name` | string | Required, 1..120 chars | Human-readable label (synthetic only) |
| `tenant_id` | string | Required | Tenant isolation boundary |
| `public_key_b64` | string | Required, base64 Ed25519 (32 bytes) | Public verification key |
| `active` | boolean | Required | Inactive principals cannot act or approve |
| `created_at_utc` | string | RFC 3339 UTC | Creation timestamp |

### 2.2 Scope (`Scope`)
Explicit allowlist entry pairing an action type with a resource pattern.

| Field | Type | Constraints | Description |
|---|---|---|---|
| `action_type` | string | Must be in `supported_action_types` | e.g., `payment.initiate`, `trade.execute`, `portfolio.rebalance`, `account.read` |
| `resource_pattern` | string | Required, exact or single trailing `*` prefix wildcard (e.g., `mock-acct-100*`) | Matched resources; bare `*` is rejected by default policy |

### 2.3 Spending Limit (`SpendingLimit`)

| Field | Type | Constraints | Description |
|---|---|---|---|
| `currency` | string | ISO-4217 in allowlist | Single currency per grant |
| `max_per_action_minor` | int64 | `>= 0` and `<= max_cumulative_minor` | Cap for any single action |
| `max_cumulative_minor` | int64 | `>= 0` | Cumulative cap over grant lifetime |
| `require_approval_above_minor` | int64 | `>= 0` | Actions with `amount_minor > require_approval_above_minor` require a signed exact-action approval (`0` requires approval for any positive amount) |

### 2.4 Delegation Grant Request & Issued Grant (`DelegationGrant`)
Issued as an RFC 7519 JWT signed with **EdDSA (Ed25519)** and stored in the grant registry.

| Field | JWT Claim | Type | Constraints |
|---|---|---|---|
| `grant_id` | `jti` | string | Unique grant identifier |
| `parent_grant_id` | `parent_grant_id` | string | Empty for root grants; parent `grant_id` for sub-delegations |
| `root_grant_id` | `root_grant_id` | string | Equals `grant_id` for root grants; inherited by descendants |
| `delegation_depth` | `delegation_depth` | int | `0 <= depth <= max_delegation_depth` |
| `can_delegate` | `can_delegate` | bool | Whether holder may issue attenuated child grants |
| `issuer_id` | `iss` | string | Authority issuer identifier |
| `delegator_id` | `delegator_id` | string | Direct delegating principal |
| `actor_id` | `sub` | string | Authorized agent principal |
| `tenant_id` | `tenant_id` | string | Tenant boundary |
| `audiences` | `aud` | []string | Non-empty subset of `allowed_audiences` |
| `scopes` | `scopes` | []Scope | Non-empty explicit allowlist |
| `allowed_counterparties` | `allowed_counterparties` | []string | Optional counterparty allowlist; empty means unconstrained on root only (cannot be cleared by child if parent restricts) |
| `spending_limit` | `spending_limit` | SpendingLimit | Monetary caps and approval threshold |
| `issued_at_utc` | `iat` | timestamp | Issuance time |
| `not_before_utc` | `nbf` | timestamp | Earliest valid time (`nbf >= iat`) |
| `expires_at_utc` | `exp` | timestamp | Expiry (`0 < exp - iat <= max_grant_ttl_seconds`) |

**Monotonic Attenuation Invariants (Sub-Delegation):**
For any child grant $C$ derived from parent grant $P$:
1. $P.\text{can\_delegate} = \text{true}$ and $C.\text{delegation\_depth} = P.\text{delegation\_depth} + 1 \le \text{max\_delegation\_depth}$.
2. $C.\text{tenant\_id} = P.\text{tenant\_id}$ and $C.\text{delegator\_id} = P.\text{actor\_id}$.
3. $C.\text{audiences} \subseteq P.\text{audiences}$.
4. Every scope $s \in C.\text{scopes}$ is subsumed by at least one scope in $P.\text{scopes}$ (exact `action_type` match and narrower or equal `resource_pattern`).
5. $C.\text{currency} = P.\text{currency}$.
6. $C.\text{max\_per\_action\_minor} \le P.\text{max\_per\_action\_minor}$.
7. $C.\text{max\_cumulative\_minor} \le P.\text{max\_cumulative\_minor} - P.\text{spent\_cumulative\_minor}$.
8. $C.\text{require\_approval\_above\_minor} \le P.\text{require\_approval\_above\_minor}$.
9. $C.\text{expires\_at\_utc} \le P.\text{expires\_at\_utc}$ and $C.\text{not\_before\_utc} \ge P.\text{not\_before\_utc}$.
10. If $P.\text{allowed\_counterparties}$ is non-empty, then $C.\text{allowed\_counterparties}$ must be non-empty and $C.\text{allowed\_counterparties} \subseteq P.\text{allowed\_counterparties}$.

### 2.5 Action Payload (`ActionPayload`)
Represents a simulated financial action submitted by an agent for enforcement.

| Field | Type | Constraints | Description |
|---|---|---|---|
| `action_id` | string | Required | Client-supplied idempotency/correlation ID |
| `action_type` | string | Must be in `supported_action_types` | Operation type |
| `audience` | string | Required, in `allowed_audiences` | Target mock financial service |
| `tenant_id` | string | Required | Must match grant tenant |
| `resource_id` | string | Required | Target mock account/desk/portfolio ID |
| `counterparty_id` | string | Optional (required for `payment.initiate`) | Mock counterparty identifier |
| `amount_minor` | int64 | `>= 0` (`0` allowed only for read-only actions) | Monetary amount in minor units |
| `currency` | string | ISO-4217 (required when `amount_minor > 0`) | Currency code |
| `metadata` | map[string]string | Optional | Additional attributes (redacted in logs if key matches redaction list) |

**Canonical Action Digest (`ActionDigest`):**
```text
canonical_bytes = "aiap.action.v1:" || canonical_json({
  action_id, action_type, amount_minor, audience,
  counterparty_id, currency, metadata_sorted, resource_id, tenant_id
})
action_digest = hex(SHA-256(canonical_bytes))
```
Because `metadata` keys are sorted lexicographically and all struct fields appear in a fixed deterministic JSON encoding with no whitespace, any modification (even 1 minor unit in `amount_minor` or a changed `counterparty_id`) alters `action_digest`.

### 2.6 Approval Record (`ApprovalRecord`)
Single-use, exact-action cryptographic approval signed by an active `human_delegator` or `service_delegator`.

| Field | Type | Constraints | Description |
|---|---|---|---|
| `approval_id` | string | Required, unique | Approval identifier |
| `grant_id` | string | Required | Bound grant ID |
| `actor_id` | string | Required | Bound agent ID |
| `approver_id` | string | Required | Active delegator principal ID |
| `action_digest` | string | Required, 64-char hex SHA-256 | Exact-action digest |
| `nonce` | string | Required, unique per grant | Replay protection nonce |
| `issued_at_utc` | string | RFC 3339 UTC | Issuance timestamp |
| `expires_at_utc` | string | RFC 3339 UTC | Expiry (`<= max_approval_ttl_seconds`) |
| `signature_b64` | string | Required, base64 Ed25519 signature | Signature over `"aiap.approval.v1:" \|\| canonical_approval_payload` |

---

## 3. Output Contracts

### 3.1 Authorization Decision (`AuthorizationDecision`)

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | Stable unique decision identifier |
| `sequence_no` | int64 | Monotonic audit log sequence number |
| `decision` | enum | `ALLOW` or `DENY` |
| `reason_code` | string | Stable machine-readable code (see Section 4) |
| `reason_detail` | string | Human-readable redacted explanation |
| `policy_version` | string | Policy version evaluated |
| `grant_id` | string | Grant ID (if parsed) |
| `actor_id` | string | Actor ID (if parsed) |
| `action_digest` | string | Computed canonical digest of the submitted action |
| `approval_id` | string | Consumed or rejected approval ID (empty if none) |
| `remaining_cumulative_minor` | int64 | Remaining cumulative allowance on the grant after decision |
| `evaluated_at_utc` | string | Evaluation timestamp (UTC) |
| `audit_entry_hash` | string | SHA-256 hash of the persisted audit record |

---

## 4. Validation and Enforcement Error Taxonomy

| Code | Category | Meaning |
|---|---|---|
| `ALLOW_AUTHORIZED` | Allow | All cryptographic, policy, limit, revocation, and approval checks passed |
| `ERR_INVALID_CONFIG` | Config | Missing or invalid configuration parameter |
| `ERR_INVALID_INPUT` | Validation | Malformed request, negative amount, empty required field, invalid timestamp |
| `ERR_UNSUPPORTED_ACTION` | Validation | `action_type` not in configured `supported_action_types` |
| `ERR_UNSUPPORTED_CURRENCY` | Validation | `currency` not in configured `supported_currencies` |
| `ERR_TOKEN_MALFORMED` | Crypto | Grant JWT cannot be parsed or is missing required claims |
| `ERR_TOKEN_INVALID_ALG` | Crypto | JWT header `alg` is not `EdDSA` (blocks `none`/HS256 downgrade) |
| `ERR_TOKEN_INVALID_SIG` | Crypto | Ed25519 signature verification failed |
| `ERR_GRANT_EXPIRED` | Grant | Current time `>= expires_at_utc` (plus configured skew) |
| `ERR_GRANT_NOT_YET_VALID` | Grant | Current time `< not_before_utc` |
| `ERR_GRANT_NOT_FOUND` | Grant | Grant ID is not registered in policy store |
| `ERR_GRANT_TOKEN_MISMATCH` | Grant | Presented token hash does not match registered grant |
| `ERR_GRANT_REVOKED` | Revocation | Grant, an ancestor grant in its chain, or actor/delegator is revoked |
| `ERR_ACTOR_INACTIVE` | Identity | Actor principal is disabled or missing |
| `ERR_TENANT_MISMATCH` | Boundary | Action tenant does not match grant tenant |
| `ERR_AUDIENCE_MISMATCH` | Policy | Action `audience` not in grant `aud` claim |
| `ERR_SCOPE_DENIED` | Policy | Action type + resource not matched by any scope in grant |
| `ERR_COUNTERPARTY_DENIED` | Policy | Counterparty not permitted by grant's `allowed_counterparties` |
| `ERR_CURRENCY_MISMATCH` | Policy | Action currency differs from grant spending limit currency |
| `ERR_PER_ACTION_LIMIT_EXCEEDED` | Limits | `amount_minor > max_per_action_minor` |
| `ERR_CUMULATIVE_LIMIT_EXCEEDED` | Limits | Action would exceed grant or ancestor `max_cumulative_minor` |
| `ERR_APPROVAL_REQUIRED` | Approval | `amount_minor > require_approval_above_minor` and no approval provided |
| `ERR_APPROVAL_INVALID_SIG` | Approval | Approval signature failed Ed25519 verification or approver unauthorized |
| `ERR_APPROVAL_EXPIRED` | Approval | Approval expired at evaluation time |
| `ERR_APPROVAL_BINDING_MISMATCH` | Approval | Approval `grant_id` or `actor_id` does not match request |
| `ERR_APPROVAL_PAYLOAD_MISMATCH` | Approval | Approval `action_digest` does not match recomputed action digest (altered amount/payload) |
| `ERR_APPROVAL_ALREADY_USED` | Approval | Approval was already consumed by a prior decision (replay/duplicate blocked) |
| `ERR_DELEGATION_NOT_ALLOWED` | Delegation | Parent grant has `can_delegate = false` |
| `ERR_DELEGATION_DEPTH_EXCEEDED` | Delegation | Sub-delegation exceeds `max_delegation_depth` |
| `ERR_DELEGATION_ESCALATION` | Delegation | Child grant attempts to widen scope, audience, counterparty, TTL, spending limit, or approval threshold |
| `ERR_AUDIT_TAMPER_DETECTED` | Audit | Audit hash chain verification failed during replay |
