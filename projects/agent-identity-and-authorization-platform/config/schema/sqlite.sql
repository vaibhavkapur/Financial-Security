-- SQLite schema for Agent Identity and Authorization Platform (AIAP)
-- Educational/research prototype; mock financial actions only.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('human_delegator', 'service_delegator', 'agent')),
    display_name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    parent_grant_id TEXT NOT NULL DEFAULT '',
    root_grant_id TEXT NOT NULL,
    delegation_depth INTEGER NOT NULL CHECK (delegation_depth >= 0),
    can_delegate INTEGER NOT NULL DEFAULT 0,
    issuer_id TEXT NOT NULL,
    delegator_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    audiences_json TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    allowed_counterparties_json TEXT NOT NULL,
    currency TEXT NOT NULL,
    max_per_action_minor INTEGER NOT NULL CHECK (max_per_action_minor >= 0),
    max_cumulative_minor INTEGER NOT NULL CHECK (max_cumulative_minor >= 0),
    spent_cumulative_minor INTEGER NOT NULL DEFAULT 0 CHECK (spent_cumulative_minor >= 0),
    require_approval_above_minor INTEGER NOT NULL CHECK (require_approval_above_minor >= 0),
    issued_at_utc TEXT NOT NULL,
    not_before_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_seq INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grants_actor ON grants(actor_id);
CREATE INDEX IF NOT EXISTS idx_grants_parent ON grants(parent_grant_id);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL CHECK (target_type IN ('grant', 'actor', 'delegator')),
    target_id TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at_utc TEXT NOT NULL,
    revoked_seq INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_target ON revocations(target_type, target_id);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    nonce TEXT NOT NULL,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    consumed_at_utc TEXT,
    consumed_by_decision_id TEXT,
    UNIQUE(grant_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_approvals_digest ON approvals(action_digest);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence_no INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    parent_grant_id TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL,
    delegator_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    action_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT '',
    action_digest TEXT NOT NULL,
    approval_id TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'EVENT')),
    reason_code TEXT NOT NULL,
    reason_detail TEXT NOT NULL,
    redacted_payload_json TEXT NOT NULL,
    replay_envelope_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sequence_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    current_seq INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO sequence_counter (id, current_seq) VALUES (1, 0);
