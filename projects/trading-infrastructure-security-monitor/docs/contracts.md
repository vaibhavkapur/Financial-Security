# Data Contracts — Trading Infrastructure Security Monitor

**Contract Schema Version:** `1.0.0`

## 1. Units, Identifiers, and Timestamp Semantics

- **Timestamps:** All input timestamps MUST be valid RFC3339 / RFC3339Nano strings with timezone offset or `Z`. During normalization, timestamps are converted to **UTC** (`occurred_at`) and also emitted as integer epoch milliseconds (`occurred_at_unix_ms`, unit: `ms`).
- **Durations & Windows:** All configured windows and gap thresholds use **seconds** (`correlation_window_seconds`, `telemetry_gap_threshold_seconds`, `brute_force_window_seconds`, `order_burst_window_seconds`).
- **Identifiers:**
  - `actor`, `service`, `host`, `action`, `outcome` are canonicalized to trimmed lowercase strings.
  - `change_ticket` is canonicalized to trimmed uppercase (e.g., `CHG-2026-1001`).
  - `artifact_sha256` is canonicalized to trimmed lowercase hex.
  - Output identifiers (`RUN-*`, `ALT-*`, `CASE-*`, `PROP-*`, `AUD-*`) are deterministic SHA-256 content-addressed 12-hex-character prefixed IDs (`contracts.StableID`).
- **Monetary / Quantity Units:** Synthetic `order_audit` payloads may include `notional_usd` (synthetic USD, strictly mock/non-live) for contextual evidence only.

## 2. Canonical Input Contract (`RawEvent`)

Inputs are newline-delimited JSON (`.jsonl`), one `RawEvent` per line:

| Field | Type | Required | Constraints |
|---|---|---|---|
| `event_id` | string | Yes | Non-empty unique source event identifier |
| `event_type` | enum string | Yes | One of `auth_log`, `config_diff`, `deployment_audit`, `order_audit` |
| `timestamp` | string | Yes | Valid RFC3339 / RFC3339Nano timestamp |
| `actor` | string | Yes | Non-empty user or service principal |
| `service` | string | Yes | Non-empty synthetic trading service name |
| `host` | string | Yes | Non-empty host identifier |
| `action` | string | Yes | Non-empty action verb (e.g. `login`, `role_grant`, `config_edit`, `deploy_release`, `risk_limit_override`) |
| `outcome` | string | No | Defaults to `"unknown"` if omitted (`success`, `failure`, etc.) |
| `source_ip` | string | No | Must parse as valid IPv4/IPv6 if non-empty |
| `change_ticket` | string | No | Optional change control ticket identifier |
| `session_id` | string | No | Optional session identifier (redacted if token-like) |
| `payload` | object | Conditional | Event-type required keys below |

### Event-Type Specific Payload Requirements

- `auth_log`: optional `auth_method`, `target_role`, `ticket_note`.
- `config_diff`: **requires** `payload.config_path` (non-empty string); optional `diff_summary`.
- `deployment_audit`: **requires** `payload.artifact_sha256` (non-empty string); optional `release_version`.
- `order_audit`: **requires** `payload.order_id` (non-empty string); optional `symbol`, `notional_usd`.

## 3. Redaction Contract

Any key matching `config/redaction_policy.json` (`sensitive_field_names`, substring match, case-insensitive) or string matching `value_patterns` (`bearer_token`, `jwt_token`, `synthetic_api_key`, `pem_private_key`, `inline_secret_assignment`) is replaced with `[REDACTED]`. A `RedactionRecord` (`field_path`, `reason`, `value_sha256_prefix`) is attached to `NormalizedEvent.redacted_fields`.

## 4. Typed Validation & Operational Errors

| Error Constant | Meaning |
|---|---|
| `ErrMissingConfig` | Missing config, policy, rules directory, or input/replay file |
| `ErrInvalidConfig` | Malformed JSON/YAML, non-deny-by-default policy, invalid CIDR/regex/condition |
| `ErrUnsupportedEventType` | `event_type` outside the 4 canonical event types |
| `ErrValidationFailed` | Missing required fields, invalid IP, malformed JSON line, invalid proposal transition |
| `ErrInvalidTimestamp` | Timestamp does not parse as RFC3339 / RFC3339Nano |
| `ErrLiveContainmentProhibited` | Attempt to configure or execute live containment |
| `ErrUnauthorizedReviewer` | Reviewer or suppression approver not in `authorized_reviewers` |
| `ErrSelfApprovalProhibited` | Reviewer matches proposal requester or case primary actor |
| `ErrInvalidSuppression` | Wildcard suppression, missing ticket/reason, or invalid `expires_at` |
| `ErrAuditChainTampered` | Hash-chain sequence or SHA-256 verification mismatch |

## 5. Canonical Output Contracts

- **`RunReport`:** `{ metadata, metrics, telemetry_gaps, validation_errors, alerts, cases, containment_proposals, reviewer_audit_log }`.
- **`Alert`:** Always includes `alert_id`, `rule_id`, `severity`, `source_event_ids` (non-empty), `suppressed`, and `evidence`.
- **`Case`:** Correlated non-suppressed alerts with `case_id`, `severity`, `primary_actor`, `alert_ids`, `source_event_ids`, `correlation_reasons`, `timeline`, and `recommended_actions` (simulation-only).
- **`EvaluationReport`:** Reports `true_positives`, `false_positives`, `false_negatives`, `recall`, `precision`, `f1_score`, `all_alerts_traced`, and `live_containment_count`.

## 6. Fixture Coverage Map

| Fixture Class | File Path |
|---|---|
| Valid reference & hand-calculated oracle | `data/fixtures/reference/reference_events.jsonl`, `expected_oracle.json` |
| Domain correctness (authorized vs unexpected) | `data/fixtures/scenarios/authorized_vs_unexpected_config.jsonl` |
| Resilience (missing telemetry & duplicates) | `data/fixtures/scenarios/missing_telemetry_and_duplicates.jsonl` |
| Boundary (suppression expiry & reviewer audit) | `data/fixtures/scenarios/suppression_and_reviewer_audit.jsonl` |
| Full synthetic evaluation dataset | `data/fixtures/scenarios/synthetic_eval_dataset.jsonl`, `synthetic_eval_ground_truth.json` |
| Invalid & unsupported inputs | `data/fixtures/invalid/invalid_events.jsonl` |
