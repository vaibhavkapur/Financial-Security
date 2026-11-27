# Operator & Developer Runbook

## 1. Prerequisites

- Go `1.24+` (verified on Go `1.27.1` darwin/arm64)
- No network access or external database required for offline lab execution.

## 2. Standard Commands

Run from `projects/trading-infrastructure-security-monitor/`:

```bash
# Validate configuration, security policy, redaction policy, and Sigma rules
make build
./bin/tism validate-config --config config/monitor_config.json

# Run full test suite (unit, integration, Sigma regression, boundary, acceptance) with race detector
./scripts/validate.sh

# Run end-to-end demo (detection + correlation + dual-control containment simulation + evaluation)
./scripts/run_demo.sh

# Regenerate all versioned machine-readable reports in reports/
./scripts/generate_reports.sh

# Run performance benchmarks
make bench
```

## 3. Replay and Rerun Procedure

To archive normalized/redacted events and replay them later (e.g., after adding a new Sigma rule or verifying crash recovery):

```bash
# Step 1: Run and persist normalized events checkpoint
go run ./src/cmd/tism run \
  --config config/monitor_config.json \
  --input data/fixtures/reference/reference_events.jsonl \
  --replay-out /tmp/tism_normalized.jsonl \
  --output /tmp/tism_run1.json

# Step 2: Replay from normalized checkpoint
go run ./src/cmd/tism replay \
  --config config/monitor_config.json \
  --input /tmp/tism_normalized.jsonl \
  --output /tmp/tism_run2.json
```

Logical `alerts`, `cases`, and `containment_proposals` will match identically.

## 4. Diagnostics and Recovery Procedures

| Symptom / Diagnostic | Meaning | Operator Action |
|---|---|---|
| `missing configuration: ...` (`ErrMissingConfig`) | Config file, policy JSON, rules directory, or input path not found | Verify working directory and `--config` / `--input` paths; run `tism validate-config`. |
| `automatic or live containment is strictly prohibited` (`ErrLiveContainmentProhibited`) | Config attempted `containment_mode != "simulation_only"` or `live_containment_enabled: true` | Restore `containment_mode: "simulation_only"` and `live_containment_enabled: false`. Live containment is out of scope. |
| `metrics.events_invalid > 0` | Malformed JSON lines or unsupported `event_type` in input | Inspect `report.validation_errors` for exact `line_number` and `error`; fix upstream producer schema and rerun. |
| `metrics.telemetry_gaps_detected > 0` or `TISM-HEALTH-001` | Expected source emitted 0 events or exceeded `telemetry_gap_threshold_seconds` | Do **not** treat the window as clean. Check upstream log forwarders for the `missing_source` listed in `report.telemetry_gaps`, backfill missing logs, and replay. |
| `metrics.events_deduplicated > 0` | Duplicate event IDs or identical canonical payloads received | Expected during log-shipper retries; verify no alert count inflation occurred. |
| `ErrUnauthorizedReviewer` / `ErrSelfApprovalProhibited` | Containment review violated RBAC or separation-of-duties | Assign an independent reviewer listed in `config/policy.json` -> `authorized_reviewers` (2 distinct reviewers for `critical`). |
| `ErrAuditChainTampered` | Hash chain mismatch in `reviewer_audit_log` | Treat audit log as compromised; preserve raw artifacts and investigate unauthorized modification. |
