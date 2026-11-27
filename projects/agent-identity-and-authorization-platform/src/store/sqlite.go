package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

const sqliteDDL = `
PRAGMA foreign_keys = ON;

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
`

// SQLiteStore implements Store using pure-Go modernc.org/sqlite with strict linearizable transactions.
type SQLiteStore struct {
	db   *sql.DB
	txMu sync.Mutex
}

// NewSQLiteStore opens and initializes a SQLite store (in-memory or on-disk).
func NewSQLiteStore(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}
	if _, err := db.ExecContext(ctx, sqliteDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// DB exposes the underlying *sql.DB exclusively for controlled tamper-detection tests.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// WithTx executes fn inside a serialized BEGIN IMMEDIATE SQLite transaction.
func (s *SQLiteStore) WithTx(ctx context.Context, fn func(tx Tx) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin immediate: %w", err)
	}
	tx := &sqliteTx{conn: conn}
	if err := fn(tx); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	var out []domain.AuditEvent
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.ListAuditEvents(ctx)
		return err
	})
	return out, err
}

func (s *SQLiteStore) GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error) {
	var out *domain.DelegationGrant
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.GetGrant(ctx, grantID)
		return err
	})
	return out, err
}

func (s *SQLiteStore) GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error) {
	var out *domain.Principal
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.GetPrincipal(ctx, principalID)
		return err
	})
	return out, err
}

type sqliteTx struct {
	conn *sql.Conn
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (t *sqliteTx) UpsertPrincipal(ctx context.Context, p domain.Principal) error {
	_, err := t.conn.ExecContext(ctx, `
		INSERT INTO principals (principal_id, principal_type, display_name, tenant_id, public_key_b64, active, created_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(principal_id) DO UPDATE SET
			principal_type = excluded.principal_type,
			display_name = excluded.display_name,
			tenant_id = excluded.tenant_id,
			public_key_b64 = excluded.public_key_b64,
			active = excluded.active
	`, p.PrincipalID, string(p.PrincipalType), p.DisplayName, p.TenantID, p.PublicKeyB64, boolToInt(p.Active), p.CreatedAtUTC.UTC().Format(time.RFC3339))
	return err
}

func (t *sqliteTx) GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error) {
	row := t.conn.QueryRowContext(ctx, `
		SELECT principal_id, principal_type, display_name, tenant_id, public_key_b64, active, created_at_utc
		FROM principals WHERE principal_id = ?
	`, principalID)
	var p domain.Principal
	var pType, createdStr string
	var activeInt int
	if err := row.Scan(&p.PrincipalID, &pType, &p.DisplayName, &p.TenantID, &p.PublicKeyB64, &activeInt, &createdStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	p.PrincipalType = domain.PrincipalType(pType)
	p.Active = activeInt != 0
	ts, err := time.Parse(time.RFC3339, createdStr)
	if err != nil {
		return nil, err
	}
	p.CreatedAtUTC = ts.UTC()
	return &p, nil
}

func (t *sqliteTx) InsertGrant(ctx context.Context, g domain.DelegationGrant) error {
	audJSON, _ := json.Marshal(g.Audiences)
	scopesJSON, _ := json.Marshal(g.Scopes)
	cp := g.AllowedCounterparties
	if cp == nil {
		cp = []string{}
	}
	cpJSON, _ := json.Marshal(cp)
	_, err := t.conn.ExecContext(ctx, `
		INSERT INTO grants (
			grant_id, parent_grant_id, root_grant_id, delegation_depth, can_delegate,
			issuer_id, delegator_id, actor_id, tenant_id,
			audiences_json, scopes_json, allowed_counterparties_json,
			currency, max_per_action_minor, max_cumulative_minor, spent_cumulative_minor,
			require_approval_above_minor, issued_at_utc, not_before_utc, expires_at_utc,
			token_hash, created_seq
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		g.GrantID, g.ParentGrantID, g.RootGrantID, g.DelegationDepth, boolToInt(g.CanDelegate),
		g.IssuerID, g.DelegatorID, g.ActorID, g.TenantID,
		string(audJSON), string(scopesJSON), string(cpJSON),
		g.SpendingLimit.Currency, g.SpendingLimit.MaxPerActionMinor, g.SpendingLimit.MaxCumulativeMinor, g.SpentCumulativeMinor,
		g.SpendingLimit.RequireApprovalAboveMinor,
		g.IssuedAtUTC.UTC().Format(time.RFC3339),
		g.NotBeforeUTC.UTC().Format(time.RFC3339),
		g.ExpiresAtUTC.UTC().Format(time.RFC3339),
		g.TokenHash, g.CreatedSeq,
	)
	return err
}

func (t *sqliteTx) GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error) {
	row := t.conn.QueryRowContext(ctx, `
		SELECT
			grant_id, parent_grant_id, root_grant_id, delegation_depth, can_delegate,
			issuer_id, delegator_id, actor_id, tenant_id,
			audiences_json, scopes_json, allowed_counterparties_json,
			currency, max_per_action_minor, max_cumulative_minor, spent_cumulative_minor,
			require_approval_above_minor, issued_at_utc, not_before_utc, expires_at_utc,
			token_hash, created_seq
		FROM grants WHERE grant_id = ?
	`, grantID)
	var g domain.DelegationGrant
	var canDelInt int
	var audJSON, scopesJSON, cpJSON string
	var iatStr, nbfStr, expStr string
	if err := row.Scan(
		&g.GrantID, &g.ParentGrantID, &g.RootGrantID, &g.DelegationDepth, &canDelInt,
		&g.IssuerID, &g.DelegatorID, &g.ActorID, &g.TenantID,
		&audJSON, &scopesJSON, &cpJSON,
		&g.SpendingLimit.Currency, &g.SpendingLimit.MaxPerActionMinor, &g.SpendingLimit.MaxCumulativeMinor, &g.SpentCumulativeMinor,
		&g.SpendingLimit.RequireApprovalAboveMinor,
		&iatStr, &nbfStr, &expStr,
		&g.TokenHash, &g.CreatedSeq,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	g.CanDelegate = canDelInt != 0
	if err := json.Unmarshal([]byte(audJSON), &g.Audiences); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &g.Scopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cpJSON), &g.AllowedCounterparties); err != nil {
		return nil, err
	}
	var err error
	if g.IssuedAtUTC, err = time.Parse(time.RFC3339, iatStr); err != nil {
		return nil, err
	}
	if g.NotBeforeUTC, err = time.Parse(time.RFC3339, nbfStr); err != nil {
		return nil, err
	}
	if g.ExpiresAtUTC, err = time.Parse(time.RFC3339, expStr); err != nil {
		return nil, err
	}
	return &g, nil
}

func (t *sqliteTx) GetGrantChain(ctx context.Context, grantID string) ([]domain.DelegationGrant, error) {
	var chain []domain.DelegationGrant
	seen := make(map[string]bool)
	curr := grantID
	for curr != "" {
		if seen[curr] {
			return nil, fmt.Errorf("delegation cycle detected at grant %q", curr)
		}
		seen[curr] = true
		g, err := t.GetGrant(ctx, curr)
		if err != nil {
			return nil, err
		}
		if g == nil {
			return nil, nil
		}
		chain = append(chain, *g)
		curr = g.ParentGrantID
	}
	return chain, nil
}

func (t *sqliteTx) AddGrantSpend(ctx context.Context, grantIDs []string, deltaMinor int64) error {
	if deltaMinor == 0 {
		return nil
	}
	for _, id := range grantIDs {
		res, err := t.conn.ExecContext(ctx, `
			UPDATE grants
			SET spent_cumulative_minor = spent_cumulative_minor + ?
			WHERE grant_id = ? AND spent_cumulative_minor + ? <= max_cumulative_minor
		`, deltaMinor, id, deltaMinor)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return domain.NewDomainError(domain.ReasonCumulativeLimitExceeded, "concurrent cumulative spending cap exceeded on grant %q", id)
		}
	}
	return nil
}

func (t *sqliteTx) InsertRevocation(ctx context.Context, r domain.RevocationRecord) error {
	_, err := t.conn.ExecContext(ctx, `
		INSERT INTO revocations (revocation_id, target_type, target_id, revoked_by, reason, revoked_at_utc, revoked_seq)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, r.RevocationID, string(r.TargetType), r.TargetID, r.RevokedBy, r.Reason, r.RevokedAtUTC.UTC().Format(time.RFC3339), r.RevokedSeq)
	return err
}

func (t *sqliteTx) IsRevoked(ctx context.Context, targetType domain.RevocationTarget, targetID string) (bool, string, error) {
	row := t.conn.QueryRowContext(ctx, `
		SELECT reason FROM revocations WHERE target_type = ? AND target_id = ? ORDER BY revoked_seq ASC LIMIT 1
	`, string(targetType), targetID)
	var reason string
	if err := row.Scan(&reason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, reason, nil
}

func (t *sqliteTx) InsertApproval(ctx context.Context, a domain.ApprovalRecord) error {
	_, err := t.conn.ExecContext(ctx, `
		INSERT INTO approvals (
			approval_id, grant_id, actor_id, approver_id, action_digest, nonce,
			issued_at_utc, expires_at_utc, signature_b64
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ApprovalID, a.GrantID, a.ActorID, a.ApproverID, a.ActionDigest, a.Nonce,
		a.IssuedAtUTC.UTC().Format(time.RFC3339), a.ExpiresAtUTC.UTC().Format(time.RFC3339), a.SignatureB64)
	return err
}

func (t *sqliteTx) GetApproval(ctx context.Context, approvalID string) (*domain.ApprovalRecord, error) {
	row := t.conn.QueryRowContext(ctx, `
		SELECT approval_id, grant_id, actor_id, approver_id, action_digest, nonce,
		       issued_at_utc, expires_at_utc, signature_b64, consumed_at_utc, consumed_by_decision_id
		FROM approvals WHERE approval_id = ?
	`, approvalID)
	var a domain.ApprovalRecord
	var iatStr, expStr string
	var consumedAt, consumedBy sql.NullString
	if err := row.Scan(
		&a.ApprovalID, &a.GrantID, &a.ActorID, &a.ApproverID, &a.ActionDigest, &a.Nonce,
		&iatStr, &expStr, &a.SignatureB64, &consumedAt, &consumedBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	var err error
	if a.IssuedAtUTC, err = time.Parse(time.RFC3339, iatStr); err != nil {
		return nil, err
	}
	if a.ExpiresAtUTC, err = time.Parse(time.RFC3339, expStr); err != nil {
		return nil, err
	}
	if consumedAt.Valid {
		ts, err := time.Parse(time.RFC3339, consumedAt.String)
		if err != nil {
			return nil, err
		}
		a.ConsumedAtUTC = &ts
	}
	if consumedBy.Valid {
		a.ConsumedByDecisionID = consumedBy.String
	}
	return &a, nil
}

func (t *sqliteTx) ConsumeApproval(ctx context.Context, approvalID string, consumedAt time.Time, decisionID string) (bool, error) {
	res, err := t.conn.ExecContext(ctx, `
		UPDATE approvals
		SET consumed_at_utc = ?, consumed_by_decision_id = ?
		WHERE approval_id = ? AND consumed_at_utc IS NULL
	`, consumedAt.UTC().Format(time.RFC3339), decisionID, approvalID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (t *sqliteTx) NextSequence(ctx context.Context) (int64, error) {
	if _, err := t.conn.ExecContext(ctx, `UPDATE sequence_counter SET current_seq = current_seq + 1 WHERE id = 1`); err != nil {
		return 0, err
	}
	var seq int64
	if err := t.conn.QueryRowContext(ctx, `SELECT current_seq FROM sequence_counter WHERE id = 1`).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

func (t *sqliteTx) AppendAuditEvent(ctx context.Context, ev *domain.AuditEvent) error {
	var prevHash string
	var lastSeq int64
	row := t.conn.QueryRowContext(ctx, `SELECT sequence_no, entry_hash FROM audit_events ORDER BY sequence_no DESC LIMIT 1`)
	if err := row.Scan(&lastSeq, &prevHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lastSeq = 0
			prevHash = domain.GenesisAuditHash
		} else {
			return err
		}
	}
	ev.SequenceNo = lastSeq + 1
	ev.PrevHash = prevHash
	ev.TimestampUTC = ev.TimestampUTC.UTC().Truncate(time.Second)
	ev.EntryHash = domain.ComputeAuditEntryHash(*ev)

	_, err := t.conn.ExecContext(ctx, `
		INSERT INTO audit_events (
			sequence_no, decision_id, event_type, timestamp_utc, policy_version,
			grant_id, parent_grant_id, actor_id, delegator_id, audience,
			action_type, resource_id, amount_minor, currency, action_digest,
			approval_id, decision, reason_code, reason_detail,
			redacted_payload_json, replay_envelope_json, prev_hash, entry_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ev.SequenceNo, ev.DecisionID, ev.EventType, ev.TimestampUTC.Format(time.RFC3339), ev.PolicyVersion,
		ev.GrantID, ev.ParentGrantID, ev.ActorID, ev.DelegatorID, ev.Audience,
		ev.ActionType, ev.ResourceID, ev.AmountMinor, ev.Currency, ev.ActionDigest,
		ev.ApprovalID, string(ev.Decision), string(ev.ReasonCode), ev.ReasonDetail,
		ev.RedactedPayloadJSON, ev.ReplayEnvelopeJSON, ev.PrevHash, ev.EntryHash,
	)
	return err
}

func (t *sqliteTx) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := t.conn.QueryContext(ctx, `
		SELECT
			sequence_no, decision_id, event_type, timestamp_utc, policy_version,
			grant_id, parent_grant_id, actor_id, delegator_id, audience,
			action_type, resource_id, amount_minor, currency, action_digest,
			approval_id, decision, reason_code, reason_detail,
			redacted_payload_json, replay_envelope_json, prev_hash, entry_hash
		FROM audit_events ORDER BY sequence_no ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		var ev domain.AuditEvent
		var tsStr, decStr, codeStr string
		if err := rows.Scan(
			&ev.SequenceNo, &ev.DecisionID, &ev.EventType, &tsStr, &ev.PolicyVersion,
			&ev.GrantID, &ev.ParentGrantID, &ev.ActorID, &ev.DelegatorID, &ev.Audience,
			&ev.ActionType, &ev.ResourceID, &ev.AmountMinor, &ev.Currency, &ev.ActionDigest,
			&ev.ApprovalID, &decStr, &codeStr, &ev.ReasonDetail,
			&ev.RedactedPayloadJSON, &ev.ReplayEnvelopeJSON, &ev.PrevHash, &ev.EntryHash,
		); err != nil {
			return nil, err
		}
		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			return nil, err
		}
		ev.TimestampUTC = ts.UTC()
		ev.Decision = domain.DecisionOutcome(decStr)
		ev.ReasonCode = domain.ReasonCode(codeStr)
		events = append(events, ev)
	}
	return events, rows.Err()
}
