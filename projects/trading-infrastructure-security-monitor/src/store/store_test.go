package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

func TestMemoryAndReplayJSONLRoundTrip(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	ev := contracts.NormalizedEvent{
		EventID:       "evt-1",
		CanonicalHash: "hash-abc",
		SchemaVersion: contracts.SchemaVersion,
		EventType:     contracts.EventTypeAuthLog,
		OccurredAt:    time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC),
		Actor:         "ops-1",
		Service:       "order-router",
		Host:          "trd-ord-01",
		Action:        "login",
		Outcome:       "success",
		Attributes:    map[string]string{"auth_method": "sso"},
	}

	if err := ms.SaveNormalizedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	seen, err := ms.HasCanonicalHash(ctx, "hash-abc")
	if err != nil || !seen {
		t.Fatalf("expected canonical hash to be present")
	}

	tmp := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := WriteNormalizedJSONL(tmp, []contracts.NormalizedEvent{ev}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadNormalizedJSONL(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].EventID != "evt-1" || loaded[0].CanonicalHash != "hash-abc" {
		t.Fatalf("unexpected replay payload: %+v", loaded)
	}
}

func TestPostgresStoreRejectsNilDB(t *testing.T) {
	if _, err := NewPostgresStore(nil); !errors.Is(err, contracts.ErrMissingConfig) {
		t.Fatalf("expected ErrMissingConfig for nil postgres db, got %v", err)
	}
}
