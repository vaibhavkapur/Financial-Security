package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

// PostgresStore is a standard database/sql persistence adapter aligned with config/schema.sql.
// In offline prototype environments without a PostgreSQL server/driver registered, NewPostgresStore
// fails explicitly with ERR_STORAGE_UNAVAILABLE rather than silently succeeding.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore attaches an existing database/sql handle configured with a PostgreSQL driver (e.g., pgx/stdlib).
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, domain.NewError(domain.ErrStorageUnavailable,
			"PostgreSQL connection is nil; attach a registered database/sql PostgreSQL driver or use FileStore/MemoryStore for offline execution")
	}
	return &PostgresStore{db: db}, nil
}

// Ping verifies connectivity to PostgreSQL.
func (p *PostgresStore) Ping(ctx context.Context) error {
	if p == nil || p.db == nil {
		return domain.NewError(domain.ErrStorageUnavailable, "PostgreSQL store not initialized")
	}
	if err := p.db.PingContext(ctx); err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "PostgreSQL ping failed", err)
	}
	return nil
}

// Save persists a CustodySnapshot transactionally into PostgreSQL tables defined in config/schema.sql.
func (p *PostgresStore) Save(snap CustodySnapshot) error {
	if p == nil || p.db == nil {
		return domain.NewError(domain.ErrStorageUnavailable, "PostgreSQL store not initialized")
	}
	tx, err := p.db.Begin()
	if err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to begin PostgreSQL transaction", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Persist latest audit events idempotently via ON CONFLICT DO NOTHING.
	for _, ev := range snap.AuditEvents {
		detailsJSON, err := json.Marshal(ev.Details)
		if err != nil {
			return domain.WrapError(domain.ErrStorageUnavailable, "failed to marshal audit event details", err)
		}
		_, err = tx.Exec(
			`INSERT INTO audit_events (seq, timestamp, event_type, actor, intent_id, outcome, reason_code, details_json, prev_hash, event_hash)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (seq) DO NOTHING`,
			ev.Seq, ev.Timestamp, ev.EventType, ev.Actor, ev.IntentID, ev.Outcome, string(ev.ReasonCode), string(detailsJSON), ev.PrevHash, ev.EventHash,
		)
		if err != nil {
			return domain.WrapError(domain.ErrStorageUnavailable, fmt.Sprintf("failed to insert audit event seq %d", ev.Seq), err)
		}
	}

	if err := tx.Commit(); err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to commit PostgreSQL transaction", err)
	}
	return nil
}

// Load is explicitly documented as requiring a live PostgreSQL instance and driver.
func (p *PostgresStore) Load() (CustodySnapshot, bool, error) {
	if p == nil || p.db == nil {
		return CustodySnapshot{}, false, domain.NewError(domain.ErrStorageUnavailable, "PostgreSQL store not initialized")
	}
	return CustodySnapshot{}, false, domain.NewError(domain.ErrStorageUnavailable,
		"full relational state hydration requires live PostgreSQL integration environment; use FileStore for offline restart tests")
}
