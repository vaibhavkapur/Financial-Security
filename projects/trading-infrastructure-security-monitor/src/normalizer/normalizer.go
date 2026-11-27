package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

// Normalizer validates raw events, redacts sensitive values, and produces canonical NormalizedEvents.
type Normalizer struct {
	redactor *Redactor
	clock    func() time.Time
}

func NewNormalizer(policy contracts.RedactionPolicy, clock func() time.Time) (*Normalizer, error) {
	red, err := NewRedactor(policy)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Normalizer{
		redactor: red,
		clock:    clock,
	}, nil
}

// Normalize validates, canonicalizes, redacts, and hashes a single RawEvent.
func (n *Normalizer) Normalize(raw contracts.RawEvent) (contracts.NormalizedEvent, error) {
	if err := raw.Validate(); err != nil {
		return contracts.NormalizedEvent{}, err
	}
	ts, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
	if err != nil {
		return contracts.NormalizedEvent{}, fmt.Errorf("%w: %v", contracts.ErrInvalidTimestamp, err)
	}
	occurredUTC := ts.UTC()

	redactedPayload, redactionRecords := n.redactor.RedactMap("payload", raw.Payload)

	// Also redact top-level free-text fields in case a token leaked into session_id or action
	sessionID, sessionPat := n.redactor.RedactString(strings.TrimSpace(raw.SessionID))
	if sessionPat != "" {
		redactionRecords = append(redactionRecords, contracts.RedactionRecord{
			FieldPath:         "session_id",
			Reason:            "pattern:" + sessionPat,
			ValueSHA256Prefix: n.redactor.fingerprint(raw.SessionID),
		})
	}

	outcome := strings.ToLower(strings.TrimSpace(raw.Outcome))
	if outcome == "" {
		outcome = "unknown"
	}

	attrs := make(map[string]string)
	flattenAttributes("", redactedPayload, attrs)

	// Canonicalize type-specific attributes for uniform downstream detection
	switch raw.EventType {
	case contracts.EventTypeAuthLog:
		if _, ok := attrs["auth_method"]; !ok {
			attrs["auth_method"] = "unspecified"
		}
	case contracts.EventTypeConfigDiff:
		if p, ok := attrs["config_path"]; ok {
			attrs["config_path"] = strings.TrimSpace(p)
		}
	case contracts.EventTypeDeploymentAudit:
		if sha, ok := attrs["artifact_sha256"]; ok {
			attrs["artifact_sha256"] = strings.ToLower(strings.TrimSpace(sha))
		}
	case contracts.EventTypeOrderAudit:
		if sym, ok := attrs["symbol"]; ok {
			attrs["symbol"] = strings.ToUpper(strings.TrimSpace(sym))
		}
	}

	ev := contracts.NormalizedEvent{
		EventID:          strings.TrimSpace(raw.EventID),
		SchemaVersion:    contracts.SchemaVersion,
		EventType:        raw.EventType,
		OccurredAt:       occurredUTC,
		OccurredAtUnixMs: occurredUTC.UnixMilli(),
		IngestedAt:       n.clock().UTC(),
		Actor:            strings.ToLower(strings.TrimSpace(raw.Actor)),
		Service:          strings.ToLower(strings.TrimSpace(raw.Service)),
		Host:             strings.ToLower(strings.TrimSpace(raw.Host)),
		Action:           strings.ToLower(strings.TrimSpace(raw.Action)),
		Outcome:          outcome,
		SourceIP:         strings.TrimSpace(raw.SourceIP),
		ChangeTicket:     strings.ToUpper(strings.TrimSpace(raw.ChangeTicket)),
		SessionID:        sessionID,
		RedactedFields:   redactionRecords,
		Attributes:       attrs,
		PayloadRedacted:  redactedPayload,
	}
	ev.CanonicalHash = computeCanonicalHash(ev)
	return ev, nil
}

// RedactString exposes string redaction for telemetry/log sanitization boundaries.
func (n *Normalizer) RedactString(s string) string {
	out, _ := n.redactor.RedactString(s)
	return out
}

func flattenAttributes(prefix string, m map[string]any, out map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		switch v := m[k].(type) {
		case map[string]any:
			flattenAttributes(full, v, out)
		case []any:
			parts := make([]string, len(v))
			for i, elem := range v {
				parts[i] = fmt.Sprint(elem)
			}
			out[full] = strings.Join(parts, ",")
		case string:
			out[full] = v
		case bool:
			out[full] = strconv.FormatBool(v)
		case float64:
			if v == float64(int64(v)) {
				out[full] = strconv.FormatInt(int64(v), 10)
			} else {
				out[full] = strconv.FormatFloat(v, 'f', -1, 64)
			}
		case int:
			out[full] = strconv.Itoa(v)
		case int64:
			out[full] = strconv.FormatInt(v, 10)
		case nil:
			out[full] = ""
		default:
			out[full] = fmt.Sprint(v)
		}
	}
}

// computeCanonicalHash hashes the logical content of a normalized event (excluding IngestedAt)
// so duplicate deliveries with different arrival times or even duplicate IDs hash identically.
func computeCanonicalHash(ev contracts.NormalizedEvent) string {
	type hashInput struct {
		EventType        contracts.EventType `json:"event_type"`
		OccurredAtUnixMs int64               `json:"occurred_at_unix_ms"`
		Actor            string              `json:"actor"`
		Service          string              `json:"service"`
		Host             string              `json:"host"`
		Action           string              `json:"action"`
		Outcome          string              `json:"outcome"`
		SourceIP         string              `json:"source_ip"`
		ChangeTicket     string              `json:"change_ticket"`
		SessionID        string              `json:"session_id"`
		Attributes       map[string]string   `json:"attributes"`
	}
	raw, _ := json.Marshal(hashInput{
		EventType:        ev.EventType,
		OccurredAtUnixMs: ev.OccurredAtUnixMs,
		Actor:            ev.Actor,
		Service:          ev.Service,
		Host:             ev.Host,
		Action:           ev.Action,
		Outcome:          ev.Outcome,
		SourceIP:         ev.SourceIP,
		ChangeTicket:     ev.ChangeTicket,
		SessionID:        ev.SessionID,
		Attributes:       ev.Attributes,
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
