-- Trading Infrastructure Security Monitor (TISM)
-- PostgreSQL Reference Schema (v1.0.0)
-- Defensive lab only; stores redacted normalized events, alerts, cases,
-- containment simulation proposals, and tamper-evident reviewer audit logs.

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id            TEXT PRIMARY KEY,
    canonical_hash      TEXT NOT NULL UNIQUE,
    schema_version      TEXT NOT NULL,
    event_type          TEXT NOT NULL CHECK (event_type IN ('auth_log', 'config_diff', 'deployment_audit', 'order_audit')),
    occurred_at         TIMESTAMPTZ NOT NULL,
    ingested_at         TIMESTAMPTZ NOT NULL,
    actor               TEXT NOT NULL,
    service             TEXT NOT NULL,
    host                TEXT NOT NULL,
    action              TEXT NOT NULL,
    outcome             TEXT NOT NULL,
    source_ip           TEXT,
    change_ticket       TEXT,
    session_id          TEXT,
    redacted_fields     JSONB NOT NULL DEFAULT '[]'::jsonb,
    attributes          JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_normalized_events_occurred_at ON normalized_events (occurred_at);
CREATE INDEX IF NOT EXISTS idx_normalized_events_actor_service ON normalized_events (actor, service);

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id            TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL,
    rule_id             TEXT NOT NULL,
    rule_title          TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    occurred_at         TIMESTAMPTZ NOT NULL,
    actor               TEXT NOT NULL,
    service             TEXT NOT NULL,
    host                TEXT NOT NULL,
    summary             TEXT NOT NULL,
    source_event_ids    JSONB NOT NULL,
    suppressed          BOOLEAN NOT NULL DEFAULT FALSE,
    suppression_id      TEXT,
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_run_id ON security_alerts (run_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_actor ON security_alerts (actor);

CREATE TABLE IF NOT EXISTS security_cases (
    case_id             TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status              TEXT NOT NULL CHECK (status IN ('open', 'triaged', 'containment_simulated', 'closed')),
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    primary_actor       TEXT NOT NULL,
    affected_services   JSONB NOT NULL,
    alert_ids           JSONB NOT NULL,
    source_event_ids    JSONB NOT NULL,
    correlation_reasons JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS containment_proposals (
    proposal_id         TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL REFERENCES security_cases(case_id),
    action_type         TEXT NOT NULL,
    target              TEXT NOT NULL,
    execution_mode      TEXT NOT NULL CHECK (execution_mode = 'simulation_only'),
    severity            TEXT NOT NULL,
    requested_by        TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending_review', 'approved_simulation', 'rejected', 'simulated')),
    approvals           JSONB NOT NULL DEFAULT '[]'::jsonb,
    blast_radius        JSONB NOT NULL,
    rollback_plan       TEXT NOT NULL,
    simulated_diff      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS reviewer_audit_log (
    sequence_num        BIGINT PRIMARY KEY,
    record_id           TEXT NOT NULL UNIQUE,
    timestamp           TIMESTAMPTZ NOT NULL,
    reviewer            TEXT NOT NULL,
    action              TEXT NOT NULL,
    target_id           TEXT NOT NULL,
    decision            TEXT NOT NULL,
    rationale           TEXT NOT NULL,
    prev_hash           TEXT NOT NULL,
    record_hash         TEXT NOT NULL
);
