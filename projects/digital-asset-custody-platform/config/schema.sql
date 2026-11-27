-- PostgreSQL relational schema for Digital Asset Custody Platform (Prototype)
-- Scope: Offline/testnet custody state, ledger entries, key epochs, and hash-chained audit trail.
-- Never store real private keys or production customer credentials in these tables.

CREATE TABLE IF NOT EXISTS custody_vaults (
    vault_id           TEXT PRIMARY KEY,
    network            TEXT NOT NULL CHECK (network LIKE 'mock-%' OR network LIKE '%-testnet' OR network LIKE '%-sepolia'),
    source_address     TEXT NOT NULL,
    active_key_epoch   BIGINT NOT NULL CHECK (active_key_epoch >= 1),
    next_nonce         BIGINT NOT NULL DEFAULT 1 CHECK (next_nonce >= 1),
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_balances (
    vault_id           TEXT NOT NULL REFERENCES custody_vaults(vault_id),
    asset              TEXT NOT NULL,
    unit               TEXT NOT NULL,
    confirmed_balance  BIGINT NOT NULL CHECK (confirmed_balance >= 0),
    reserved_balance   BIGINT NOT NULL CHECK (reserved_balance >= 0 AND reserved_balance <= confirmed_balance),
    updated_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (vault_id, asset)
);

CREATE TABLE IF NOT EXISTS vault_key_epochs (
    vault_id           TEXT NOT NULL REFERENCES custody_vaults(vault_id),
    key_epoch          BIGINT NOT NULL CHECK (key_epoch >= 1),
    threshold          INT NOT NULL CHECK (threshold >= 1),
    signer_pubkeys_json JSONB NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
    activated_at       TIMESTAMPTZ NOT NULL,
    retired_at         TIMESTAMPTZ,
    PRIMARY KEY (vault_id, key_epoch)
);

CREATE TABLE IF NOT EXISTS transfer_intents (
    intent_id           TEXT PRIMARY KEY,
    intent_hash         TEXT NOT NULL UNIQUE,
    schema_version      TEXT NOT NULL,
    vault_id            TEXT NOT NULL REFERENCES custody_vaults(vault_id),
    network             TEXT NOT NULL,
    asset               TEXT NOT NULL,
    unit                TEXT NOT NULL,
    amount              BIGINT NOT NULL CHECK (amount > 0),
    source_address      TEXT NOT NULL,
    destination_address TEXT NOT NULL,
    nonce               BIGINT NOT NULL CHECK (nonce >= 1),
    requested_by        TEXT NOT NULL,
    key_epoch           BIGINT NOT NULL CHECK (key_epoch >= 1),
    policy_version      TEXT NOT NULL,
    required_approvals  INT NOT NULL CHECK (required_approvals >= 1),
    required_signers    INT NOT NULL CHECK (required_signers >= 1),
    status              TEXT NOT NULL CHECK (status IN (
        'PENDING_APPROVAL', 'DENIED', 'APPROVED', 'SIGNED',
        'BROADCAST', 'CONFIRMING', 'CONFIRMED',
        'INVALIDATED_KEY_ROTATION', 'REORGED_DROPPED', 'FAILED'
    )),
    tx_hash             TEXT,
    block_height        BIGINT,
    block_hash          TEXT,
    confirmations       INT NOT NULL DEFAULT 0,
    memo                TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (vault_id, nonce)
);

CREATE TABLE IF NOT EXISTS intent_approvals (
    intent_id          TEXT NOT NULL REFERENCES transfer_intents(intent_id),
    approver_id        TEXT NOT NULL,
    intent_hash        TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    signature_hex      TEXT NOT NULL,
    approved_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (intent_id, approver_id)
);

CREATE TABLE IF NOT EXISTS intent_signatures (
    intent_id          TEXT NOT NULL REFERENCES transfer_intents(intent_id),
    signer_id          TEXT NOT NULL,
    key_epoch          BIGINT NOT NULL,
    intent_hash        TEXT NOT NULL,
    signature_hex      TEXT NOT NULL,
    signed_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (intent_id, signer_id, key_epoch)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    entry_id           TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL REFERENCES custody_vaults(vault_id),
    asset              TEXT NOT NULL,
    intent_id          TEXT REFERENCES transfer_intents(intent_id),
    entry_type         TEXT NOT NULL CHECK (entry_type IN ('DEPOSIT', 'RESERVE', 'RELEASE', 'SETTLE', 'REORG_REVERT')),
    delta_confirmed    BIGINT NOT NULL,
    delta_reserved     BIGINT NOT NULL,
    balance_after      BIGINT NOT NULL CHECK (balance_after >= 0),
    reserved_after     BIGINT NOT NULL CHECK (reserved_after >= 0),
    created_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq                BIGINT PRIMARY KEY,
    timestamp          TIMESTAMPTZ NOT NULL,
    event_type         TEXT NOT NULL,
    actor              TEXT NOT NULL,
    intent_id          TEXT,
    outcome            TEXT NOT NULL,
    reason_code        TEXT NOT NULL,
    details_json       JSONB NOT NULL,
    prev_hash          TEXT NOT NULL,
    event_hash         TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_intents_vault_status ON transfer_intents(vault_id, status);
CREATE INDEX IF NOT EXISTS idx_ledger_vault_asset ON ledger_entries(vault_id, asset, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_intent ON audit_events(intent_id);
