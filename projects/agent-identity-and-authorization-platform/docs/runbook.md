# Operator & Developer Runbook

## 1. Prerequisites

- **Go 1.24+** (tested with Go 1.27.1 on `darwin/arm64`)
- No external database daemon required for default SQLite mode.
- Optional: PostgreSQL 15+ if running with `"driver": "postgres"` using `config/schema/postgres.sql`.

---

## 2. Quickstart Commands

Run all commands from `projects/agent-identity-and-authorization-platform/`:

### Inspect & Validate Configuration
```bash
go run ./src/cmd/agent-authz inspect-config --config config/default.json
```

### Run End-to-End Reproducible Demo
```bash
./scripts/demo.sh
# or directly:
go run ./src/cmd/agent-authz demo --config config/default.json
```

### Verify Deterministic Reference Fixtures Against Baseline
```bash
go run ./src/cmd/agent-authz verify-fixtures \
  --config config/default.json \
  --fixture data/fixtures/reference_scenario.json \
  --out reports/baseline_outputs.json
```

### Run Seeded Adversarial Delegation Evaluation
```bash
go run ./src/cmd/agent-authz evaluate \
  --config config/default.json \
  --out reports/adversarial_report.json
```

### Run Full Validation Suite (Vet, Build, Race Tests, Fixtures, Adversarial, Demo, Benchmarks)
```bash
./scripts/validate.sh
```

---

## 3. Diagnostics and Telemetry

- **Structured JSON Logs:** `PlatformService` emits `log/slog` JSON logs for `root_grant_issued`, `subgrant_issued`, `revocation_recorded`, and `authorization_decision`. Sensitive metadata keys configured in `redaction.redact_fields` are scrubbed to `[REDACTED]` before persisting to `audit_events`.
- **Diagnostic Counters:** `svc.Metrics()` exposes `grants_issued`, `sub_grants_issued`, `revocations_recorded`, `approvals_consumed`, `total_authorizations`, `allow_count`, `deny_count`, and per-reason-code deny histograms (`denies_by_reason`).
- **Audit Integrity & Replay:** Call `audit.ReplayAuditLog(events)` to verify sequence monotonicity, SHA-256 hash chaining from `GenesisAuditHash`, and 1:1 deterministic policy decision reproduction.

---

## 4. Failure Modes and Recovery Procedures

| Symptom / Error Code | Root Cause | Recovery Procedure |
|---|---|---|
| `ERR_INVALID_CONFIG` on startup | Missing config file, unknown JSON key, `deny_by_default: false`, or non-`EdDSA` signing alg | Run `agent-authz inspect-config --config <path>` to pinpoint the invalid field; restore from `config/default.json`. |
| `ERR_TOKEN_INVALID_ALG` / `ERR_TOKEN_INVALID_SIG` | Token signed with non-EdDSA algorithm, wrong key ID, or tampered payload | Reject request (already denied); inspect `audit_events` for the offending `actor_id` and rotate/revoke actor if compromise is suspected. |
| `ERR_GRANT_REVOKED` on sub-delegated grant | Leaf grant, an ancestor grant, actor, or delegator was revoked | Inspect `revocations` table by `target_id` / `root_grant_id`; re-issue a fresh bounded grant from an active delegator only after incident clearance. |
| `ERR_APPROVAL_PAYLOAD_MISMATCH` | Action payload differs from the exact canonical digest signed by the approver (e.g., altered amount or counterparty) | Do not retry with the old approval; verify intended action fields and request a fresh delegator signature over the exact payload. |
| `ERR_APPROVAL_ALREADY_USED` | Duplicate submission or replay of a previously consumed single-use approval | Check `approvals.consumed_by_decision_id` to confirm whether the original transaction succeeded; never reuse approvals. |
| `ERR_AUDIT_TAMPER_DETECTED` during replay | Direct modification, deletion, or reordering in `audit_events` | Halt enforcement immediately, preserve forensic database snapshot, identify first broken `sequence_no` from `ReplayReport.Mismatches`, and restore from verified backup. |
| Restart / crash recovery | Process restarted while using persistent on-disk SQLite or PostgreSQL | Re-open the same DSN; grants, cumulative spend, consumed approvals, revocations, and the audit hash chain are ACID-durable and resume automatically. Run `ReplayAuditLog` on startup to verify ledger integrity. |

---

## 5. Switching to PostgreSQL (Optional)

1. Provision PostgreSQL and apply `config/schema/postgres.sql`:
   ```bash
   psql "$DATABASE_URL" -f config/schema/postgres.sql
   ```
2. Update `config/default.json` (or a separate config file):
   ```json
   "storage": {
     "driver": "postgres",
     "dsn": "postgres://user:pass@localhost:5432/aiap_mock?sslmode=disable"
   }
   ```
3. Validate configuration with `agent-authz inspect-config` before starting.
