package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

// PostgresStore implements Store using github.com/jackc/pgx/v5 with SERIALIZABLE transactions.
// Schema is defined in config/schema/postgres.sql.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to PostgreSQL using pgxpool.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *PostgresStore) WithTx(ctx context.Context, fn func(tx Tx) error) error {
	pgTx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	wrapper := &postgresTx{tx: pgTx}
	if err := fn(wrapper); err != nil {
		_ = pgTx.Rollback(ctx)
		return err
	}
	return pgTx.Commit(ctx)
}

func (s *PostgresStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	var out []domain.AuditEvent
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.ListAuditEvents(ctx)
		return err
	})
	return out, err
}

func (s *PostgresStore) GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error) {
	var out *domain.DelegationGrant
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.GetGrant(ctx, grantID)
		return err
	})
	return out, err
}

func (s *PostgresStore) GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error) {
	var out *domain.Principal
	err := s.WithTx(ctx, func(tx Tx) error {
		var err error
		out, err = tx.GetPrincipal(ctx, principalID)
		return err
	})
	return out, err
}

type postgresTx struct {
	tx pgx.Tx
}

func (t *postgresTx) UpsertPrincipal(ctx context.Context, p domain.Principal) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO principals (principal_id, principal_type, display_name, tenant_id, public_key_b64, active, created_at_utc)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (principal_id) DO UPDATE SET
			principal_type = EXCLUDED.principal_type,
			display_name = EXCLUDED.display_name,
			tenant_id = EXCLUDED.tenant_id,
			public_key_b64 = EXCLUDED.public_key_b64,
			active = EXCLUDED.active
	`, p.PrincipalID, string(p.PrincipalType), p.DisplayName, p.TenantID, p.PublicKeyB64, p.Active, p.CreatedAtUTC.UTC())
	return err
}

func (t *postgresTx) GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error) {
	row := t.tx.QueryRow(ctx, `
		SELECT principal_id, principal_type, display_name, tenant_id, public_key_b64, active, created_at_utc
		FROM principals WHERE principal_id = $1
	`, principalID)
	var p domain.Principal
	var pType string
	if err := row.Scan(&p.PrincipalID, &pType, &p.DisplayName, &p.TenantID, &p.PublicKeyB64, &p.Active, &p.CreatedAtUTC); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	p.PrincipalType = domain.PrincipalType(pType)
	p.CreatedAtUTC = p.CreatedAtUTC.UTC()
	return &p, nil
}

func (t *postgresTx) InsertGrant(ctx context.Context, g domain.DelegationGrant) error {
	audJSON, _ := json.Marshal(g.Audiences)
	scopesJSON, _ := json.Marshal(g.Scopes)
	cp := g.AllowedCounterparties
	if cp == nil {
		cp = []string{}
	}
	cpJSON, _ := json.Marshal(cp)
	_, err := t.tx.Exec(ctx, `
		INSERT INTO grants (
			grant_id, parent_grant_id, root_grant_id, delegation_depth, can_delegate,
			issuer_id, delegator_id, actor_id, tenant_id,
			audiences_json, scopes_json, allowed_counterparties_json,
			currency, max_per_action_minor, max_cumulative_minor, spent_cumulative_minor,
			require_approval_above_minor, issued_at_utc, not_before_utc, expires_at_utc,
			token_hash, created_seq
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
	`,
		g.GrantID, g.ParentGrantID, g.RootGrantID, g.DelegationDepth, g.CanDelegate,
		g.IssuerID, g.DelegatorID, g.ActorID, g.TenantID,
		string(audJSON), string(scopesJSON), string(cpJSON),
		g.SpendingLimit.Currency, g.SpendingLimit.MaxPerActionMinor, g.SpendingLimit.MaxCumulativeMinor, g.SpentCumulativeMinor,
		g.SpendingLimit.RequireApprovalAboveMinor,
		g.IssuedAtUTC.UTC(), g.NotBeforeUTC.UTC(), g.ExpiresAtUTC.UTC(),
		g.TokenHash, g.CreatedSeq,
	)
	return err
}

func (t *postgresTx) GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error) {
	row := t.tx.QueryRow(ctx, `
		SELECT
			grant_id, parent_grant_id, root_grant_id, delegation_depth, can_delegate,
			issuer_id, delegator_id, actor_id, tenant_id,
			audiences_json, scopes_json, allowed_counterparties_json,
			currency, max_per_action_minor, max_cumulative_minor, spent_cumulative_minor,
			require_approval_above_minor, issued_at_utc, not_before_utc, expires_at_utc,
			token_hash, created_seq
		FROM grants WHERE grant_id = $1 FOR UPDATE
	`, grantID)
	var g domain.DelegationGrant
	var audJSON, scopesJSON, cpJSON []byte
	if err := row.Scan(
		&g.GrantID, &g.ParentGrantID, &g.RootGrantID, &g.DelegationDepth, &g.CanDelegate,
		&g.IssuerID, &g.DelegatorID, &g.ActorID, &g.TenantID,
		&audJSON, &scopesJSON, &cpJSON,
		&g.SpendingLimit.Currency, &g.SpendingLimit.MaxPerActionMinor, &g.SpendingLimit.MaxCumulativeMinor, &g.SpentCumulativeMinor,
		&g.SpendingLimit.RequireApprovalAboveMinor,
		&g.IssuedAtUTC, &g.NotBeforeUTC, &g.ExpiresAtUTC,
		&g.TokenHash, &g.CreatedSeq,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(audJSON, &g.Audiences); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &g.Scopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(cpJSON, &g.AllowedCounterparties); err != nil {
		return nil, err
	}
	g.IssuedAtUTC = g.IssuedAtUTC.UTC()
	g.NotBeforeUTC = g.NotBeforeUTC.UTC()
	g.ExpiresAtUTC = g.ExpiresAtUTC.UTC()
	return &g, nil
}

func (t *postgresTx) GetGrantChain(ctx context.Context, grantID string) ([]domain.DelegationGrant, error) {
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

func (t *postgresTx) AddGrantSpend(ctx context.Context, grantIDs []string, deltaMinor int64) error {
	if deltaMinor == 0 {
		return nil
	}
	for _, id := range grantIDs {
		tag, err := t.tx.Exec(ctx, `
			UPDATE grants
			SET spent_cumulative_minor = spent_cumulative_minor + $1
			WHERE grant_id = $2 AND spent_cumulative_minor + $1 <= max_cumulative_minor
		`, deltaMinor, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return domain.NewDomainError(domain.ReasonCumulativeLimitExceeded, "concurrent cumulative spending cap exceeded on grant %q", id)
		}
	}
	return nil
}

func (t *postgresTx) InsertRevocation(ctx context.Context, r domain.RevocationRecord) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO revocations (revocation_id, target_type, target_id, revoked_by, reason, revoked_at_utc, revoked_seq)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, r.RevocationID, string(r.TargetType), r.TargetID, r.RevokedBy, r.Reason, r.RevokedAtUTC.UTC(), r.RevokedSeq)
	return err
}

func (t *postgresTx) IsRevoked(ctx context.Context, targetType domain.RevocationTarget, targetID string) (bool, string, error) {
	row := t.tx.QueryRow(ctx, `
		SELECT reason FROM revocations WHERE target_type = $1 AND target_id = $2 ORDER BY revoked_seq ASC LIMIT 1
	`, string(targetType), targetID)
	var reason string
	if err := row.Scan(&reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, reason, nil
}

func (t *postgresTx) InsertApproval(ctx context.Context, a domain.ApprovalRecord) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO approvals (
			approval_id, grant_id, actor_id, approver_id, action_digest, nonce,
			issued_at_utc, expires_at_utc, signature_b64
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, a.ApprovalID, a.GrantID, a.ActorID, a.ApproverID, a.ActionDigest, a.Nonce,
		a.IssuedAtUTC.UTC(), a.ExpiresAtUTC.UTC(), a.SignatureB64)
	return err
}

func (t *postgresTx) GetApproval(ctx context.Context, approvalID string) (*domain.ApprovalRecord, error) {
	row := t.tx.QueryRow(ctx, `
		SELECT approval_id, grant_id, actor_id, approver_id, action_digest, nonce,
		       issued_at_utc, expires_at_utc, signature_b64, consumed_at_utc, consumed_by_decision_id
		FROM approvals WHERE approval_id = $1 FOR UPDATE
	`, approvalID)
	var a domain.ApprovalRecord
	var consumedAt *time.Time
	var consumedBy *string
	if err := row.Scan(
		&a.ApprovalID, &a.GrantID, &a.ActorID, &a.ApproverID, &a.ActionDigest, &a.Nonce,
		&a.IssuedAtUTC, &a.ExpiresAtUTC, &a.SignatureB64, &consumedAt, &consumedBy,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	a.IssuedAtUTC = a.IssuedAtUTC.UTC()
	a.ExpiresAtUTC = a.ExpiresAtUTC.UTC()
	if consumedAt != nil {
		utc := consumedAt.UTC()
		a.ConsumedAtUTC = &utc
	}
	if consumedBy != nil {
		a.ConsumedByDecisionID = *consumedBy
	}
	return &a, nil
}

func (t *postgresTx) ConsumeApproval(ctx context.Context, approvalID string, consumedAt time.Time, decisionID string) (bool, error) {
	tag, err := t.tx.Exec(ctx, `
		UPDATE approvals
		SET consumed_at_utc = $1, consumed_by_decision_id = $2
		WHERE approval_id = $3 AND consumed_at_utc IS NULL
	`, consumedAt.UTC(), decisionID, approvalID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (t *postgresTx) NextSequence(ctx context.Context) (int64, error) {
	var seq int64
	err := t.tx.QueryRow(ctx, `UPDATE sequence_counter SET current_seq = current_seq + 1 WHERE id = 1 RETURNING current_seq`).Scan(&seq)
	return seq, err
}

func (t *postgresTx) AppendAuditEvent(ctx context.Context, ev *domain.AuditEvent) error {
	var prevHash string
	var lastSeq int64
	row := t.tx.QueryRow(ctx, `SELECT sequence_no, entry_hash FROM audit_events ORDER BY sequence_no DESC LIMIT 1`)
	if err := row.Scan(&lastSeq, &prevHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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

	_, err := t.tx.Exec(ctx, `
		INSERT INTO audit_events (
			sequence_no, decision_id, event_type, timestamp_utc, policy_version,
			grant_id, parent_grant_id, actor_id, delegator_id, audience,
			action_type, resource_id, amount_minor, currency, action_digest,
			approval_id, decision, reason_code, reason_detail,
			redacted_payload_json, replay_envelope_json, prev_hash, entry_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
	`,
		ev.SequenceNo, ev.DecisionID, ev.EventType, ev.TimestampUTC, ev.PolicyVersion,
		ev.GrantID, ev.ParentGrantID, ev.ActorID, ev.DelegatorID, ev.Audience,
		ev.ActionType, ev.ResourceID, ev.AmountMinor, ev.Currency, ev.ActionDigest,
		ev.ApprovalID, string(ev.Decision), string(ev.ReasonCode), ev.ReasonDetail,
		ev.RedactedPayloadJSON, ev.ReplayEnvelopeJSON, ev.PrevHash, ev.EntryHash,
	)
	return err
}

func (t *postgresTx) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := t.tx.Query(ctx, `
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
		var decStr, codeStr string
		if err := rows.Scan(
			&ev.SequenceNo, &ev.DecisionID, &ev.EventType, &ev.TimestampUTC, &ev.PolicyVersion,
			&ev.GrantID, &ev.ParentGrantID, &ev.ActorID, &ev.DelegatorID, &ev.Audience,
			&ev.ActionType, &ev.ResourceID, &ev.AmountMinor, &ev.Currency, &ev.ActionDigest,
			&ev.ApprovalID, &decStr, &codeStr, &ev.ReasonDetail,
			&ev.RedactedPayloadJSON, &ev.ReplayEnvelopeJSON, &ev.PrevHash, &ev.EntryHash,
		); err != nil {
			return nil, err
		}
		ev.TimestampUTC = ev.TimestampUTC.UTC()
		ev.Decision = domain.DecisionOutcome(decStr)
		ev.ReasonCode = domain.ReasonCode(codeStr)
		events = append(events, ev)
	}
	return events, rows.Err()
}
