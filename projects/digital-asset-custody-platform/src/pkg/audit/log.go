package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	sensitiveKeyFragments = []string{"private", "secret", "seed", "mnemonic", "password", "passphrase", "api_key", "privkey"}
	longHexSecretPattern  = regexp.MustCompile(`\b[0-9a-fA-F]{128}\b`)
)

// RedactString masks obvious secret patterns so raw private key material cannot leak into logs or audit records.
func RedactString(s string) string {
	return longHexSecretPattern.ReplaceAllString(s, "[REDACTED_KEY_MATERIAL]")
}

// RedactMap deep-copies a details map while redacting sensitive keys or values.
func RedactMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lower := strings.ToLower(k)
		isSensitive := false
		for _, frag := range sensitiveKeyFragments {
			if strings.Contains(lower, frag) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			out[k] = "[REDACTED]"
			continue
		}
		switch val := v.(type) {
		case string:
			out[k] = RedactString(val)
		case map[string]any:
			out[k] = RedactMap(val)
		default:
			out[k] = val
		}
	}
	return out
}

// Log is an append-only, hash-chained, redacted audit trail.
type Log struct {
	mu     sync.RWMutex
	events []domain.AuditEvent
}

func NewLog() *Log {
	return &Log{events: make([]domain.AuditEvent, 0)}
}

// Append records a new redacted audit event and links its SHA-256 hash to the previous event.
func (l *Log) Append(now time.Time, eventType, actor, intentID, outcome string, reasonCode domain.ErrorCode, details map[string]any) domain.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()

	prevHash := GenesisHash
	if len(l.events) > 0 {
		prevHash = l.events[len(l.events)-1].EventHash
	}
	ev := domain.AuditEvent{
		Seq:        uint64(len(l.events) + 1),
		Timestamp:  now.UTC().Format(time.RFC3339),
		EventType:  eventType,
		Actor:      actor,
		IntentID:   intentID,
		Outcome:    outcome,
		ReasonCode: reasonCode,
		Details:    RedactMap(details),
		PrevHash:   prevHash,
	}
	ev.EventHash = computeEventHash(ev)
	l.events = append(l.events, ev)
	return ev
}

// Events returns a copy of all recorded audit events.
func (l *Log) Events() []domain.AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]domain.AuditEvent, len(l.events))
	copy(out, l.events)
	return out
}

// Restore replaces internal events from a persisted snapshot after verifying chain integrity.
func (l *Log) Restore(events []domain.AuditEvent) error {
	if err := VerifyEvents(events); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = make([]domain.AuditEvent, len(events))
	copy(l.events, events)
	return nil
}

// VerifyChain validates sequential numbering and SHA-256 hash links across all audit events.
func (l *Log) VerifyChain() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return VerifyEvents(l.events)
}

// VerifyEvents validates a slice of audit events independently.
func VerifyEvents(events []domain.AuditEvent) error {
	prev := GenesisHash
	for i, ev := range events {
		expectedSeq := uint64(i + 1)
		if ev.Seq != expectedSeq {
			return fmt.Errorf("audit chain sequence gap at index %d: got %d expected %d", i, ev.Seq, expectedSeq)
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("audit chain prev_hash mismatch at seq %d", ev.Seq)
		}
		computed := computeEventHash(ev)
		if ev.EventHash != computed {
			return fmt.Errorf("audit event hash tampered at seq %d", ev.Seq)
		}
		prev = ev.EventHash
	}
	return nil
}

func computeEventHash(ev domain.AuditEvent) string {
	type hashPayload struct {
		Seq        uint64           `json:"seq"`
		Timestamp  string           `json:"timestamp"`
		EventType  string           `json:"event_type"`
		Actor      string           `json:"actor"`
		IntentID   string           `json:"intent_id,omitempty"`
		Outcome    string           `json:"outcome"`
		ReasonCode domain.ErrorCode `json:"reason_code,omitempty"`
		Details    map[string]any   `json:"details,omitempty"`
		PrevHash   string           `json:"prev_hash"`
	}
	raw, _ := json.Marshal(hashPayload{
		Seq:        ev.Seq,
		Timestamp:  ev.Timestamp,
		EventType:  ev.EventType,
		Actor:      ev.Actor,
		IntentID:   ev.IntentID,
		Outcome:    ev.Outcome,
		ReasonCode: ev.ReasonCode,
		Details:    ev.Details,
		PrevHash:   ev.PrevHash,
	})
	sum := sha256.Sum256(append([]byte("CUSTODY_AUDIT_V1:"), raw...))
	return hex.EncodeToString(sum[:])
}
