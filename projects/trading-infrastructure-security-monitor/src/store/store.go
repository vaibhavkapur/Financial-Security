package store

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"trading-infrastructure-security-monitor/src/contracts"
)

// EventStore defines the storage adapter boundary for normalized events, deduplication, and replay.
type EventStore interface {
	HasCanonicalHash(ctx context.Context, hash string) (bool, error)
	SaveNormalizedEvent(ctx context.Context, ev contracts.NormalizedEvent) error
	ListNormalizedEvents(ctx context.Context) ([]contracts.NormalizedEvent, error)
	SaveReport(ctx context.Context, report contracts.RunReport) error
}

// MemoryStore is a deterministic in-memory store used for offline runs, unit tests, and replay.
type MemoryStore struct {
	seenHashes map[string]bool
	events     []contracts.NormalizedEvent
	reports    map[string]contracts.RunReport
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		seenHashes: make(map[string]bool),
		events:     make([]contracts.NormalizedEvent, 0),
		reports:    make(map[string]contracts.RunReport),
	}
}

func (m *MemoryStore) HasCanonicalHash(_ context.Context, hash string) (bool, error) {
	return m.seenHashes[hash], nil
}

func (m *MemoryStore) SaveNormalizedEvent(_ context.Context, ev contracts.NormalizedEvent) error {
	m.seenHashes[ev.CanonicalHash] = true
	m.events = append(m.events, ev)
	return nil
}

func (m *MemoryStore) ListNormalizedEvents(_ context.Context) ([]contracts.NormalizedEvent, error) {
	out := make([]contracts.NormalizedEvent, len(m.events))
	copy(out, m.events)
	return out, nil
}

func (m *MemoryStore) SaveReport(_ context.Context, report contracts.RunReport) error {
	m.reports[report.Metadata.RunID] = report
	return nil
}

// WriteNormalizedJSONL persists normalized events to a JSONL file for deterministic replay.
func WriteNormalizedJSONL(path string, events []contracts.NormalizedEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

// LoadNormalizedJSONL reads previously normalized events for restart/replay runs.
func LoadNormalizedJSONL(path string) ([]contracts.NormalizedEvent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: replay file %s", contracts.ErrMissingConfig, path)
		}
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	events := make([]contracts.NormalizedEvent, 0, len(lines))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var ev contracts.NormalizedEvent
		if err := json.Unmarshal([]byte(trimmed), &ev); err != nil {
			return nil, fmt.Errorf("%w: replay line %d: %v", contracts.ErrValidationFailed, i+1, err)
		}
		events = append(events, ev)
	}
	return events, nil
}

// PostgresStore adapts EventStore to PostgreSQL using config/postgres_schema.sql.
// In offline lab environments without a live PostgreSQL server, NewPostgresStore fails fast
// when db is nil instead of silently succeeding.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: postgres sql.DB connection is nil (live database disabled in offline lab)", contracts.ErrMissingConfig)
	}
	return &PostgresStore{db: db}, nil
}

func (p *PostgresStore) HasCanonicalHash(ctx context.Context, hash string) (bool, error) {
	var exists bool
	err := p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM normalized_events WHERE canonical_hash = $1)`, hash).Scan(&exists)
	return exists, err
}

func (p *PostgresStore) SaveNormalizedEvent(ctx context.Context, ev contracts.NormalizedEvent) error {
	redactedJSON, _ := json.Marshal(ev.RedactedFields)
	attrsJSON, _ := json.Marshal(ev.Attributes)
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO normalized_events (
			event_id, canonical_hash, schema_version, event_type, occurred_at, ingested_at,
			actor, service, host, action, outcome, source_ip, change_ticket, session_id,
			redacted_fields, attributes
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (canonical_hash) DO NOTHING`,
		ev.EventID, ev.CanonicalHash, ev.SchemaVersion, string(ev.EventType), ev.OccurredAt, ev.IngestedAt,
		ev.Actor, ev.Service, ev.Host, ev.Action, ev.Outcome, ev.SourceIP, ev.ChangeTicket, ev.SessionID,
		string(redactedJSON), string(attrsJSON),
	)
	return err
}

func (p *PostgresStore) ListNormalizedEvents(ctx context.Context) ([]contracts.NormalizedEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT event_id, canonical_hash, schema_version, event_type, occurred_at, ingested_at,
		       actor, service, host, action, outcome, COALESCE(source_ip,''), COALESCE(change_ticket,''), COALESCE(session_id,''),
		       redacted_fields, attributes
		FROM normalized_events ORDER BY occurred_at ASC, event_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]contracts.NormalizedEvent, 0)
	for rows.Next() {
		var ev contracts.NormalizedEvent
		var et string
		var redJSON, attrJSON []byte
		if err := rows.Scan(
			&ev.EventID, &ev.CanonicalHash, &ev.SchemaVersion, &et, &ev.OccurredAt, &ev.IngestedAt,
			&ev.Actor, &ev.Service, &ev.Host, &ev.Action, &ev.Outcome, &ev.SourceIP, &ev.ChangeTicket, &ev.SessionID,
			&redJSON, &attrJSON,
		); err != nil {
			return nil, err
		}
		ev.EventType = contracts.EventType(et)
		ev.OccurredAtUnixMs = ev.OccurredAt.UnixMilli()
		_ = json.Unmarshal(redJSON, &ev.RedactedFields)
		_ = json.Unmarshal(attrJSON, &ev.Attributes)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (p *PostgresStore) SaveReport(ctx context.Context, report contracts.RunReport) error {
	for _, a := range report.Alerts {
		evIDs, _ := json.Marshal(a.SourceEventIDs)
		evMap, _ := json.Marshal(a.Evidence)
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO security_alerts (
				alert_id, run_id, rule_id, rule_title, category, severity, occurred_at,
				actor, service, host, summary, source_event_ids, suppressed, suppression_id, evidence
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (alert_id) DO NOTHING`,
			a.AlertID, report.Metadata.RunID, a.RuleID, a.RuleTitle, a.Category, string(a.Severity),
			a.OccurredAt, a.Actor, a.Service, a.Host, a.Summary, string(evIDs), a.Suppressed, a.SuppressionID, string(evMap),
		); err != nil {
			return err
		}
	}
	return nil
}
