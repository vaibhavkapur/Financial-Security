package normalizer

import (
	"strings"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

func testRedactionPolicy() contracts.RedactionPolicy {
	return contracts.RedactionPolicy{
		SchemaVersion:             contracts.SchemaVersion,
		ReplacementToken:          "[REDACTED]",
		PreserveSHA256Fingerprint: true,
		SensitiveFieldNames:       []string{"password", "api_key", "fix_password", "token"},
		ValuePatterns: []contracts.RedactionPattern{
			{Name: "bearer_token", Pattern: `(?i)Bearer\s+[A-Za-z0-9._\-+/=]{12,}`},
			{Name: "synthetic_api_key", Pattern: `(?i)(?:sk|pk|tism|fix)_(?:live|test|sim|prod)_[A-Za-z0-9]{12,}`},
			{Name: "inline_secret_assignment", Pattern: `(?i)(password|secret|api_key|token|fix_password)\s*[:=]\s*['"]?[^\s'",;}]{4,}['"]?`},
		},
	}
}

func TestNormalizeAndRedactSecrets(t *testing.T) {
	fixedNow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	norm, err := NewNormalizer(testRedactionPolicy(), func() time.Time { return fixedNow })
	if err != nil {
		t.Fatalf("NewNormalizer failed: %v", err)
	}

	raw := contracts.RawEvent{
		EventID:   "evt-redact-01",
		EventType: contracts.EventTypeConfigDiff,
		Timestamp: "2026-06-01T10:15:00+02:00",
		Actor:     "Dev-Alice ",
		Service:   "Order-Router",
		Host:      "TRD-ORD-01",
		Action:    "Config_Edit",
		Outcome:   "Success",
		SourceIP:  "10.10.2.15",
		Payload: map[string]any{
			"config_path":  "/etc/trading/order-router/routing.yaml",
			"fix_password": "synthetic-fix-pass-999",
			"diff_summary": "updated header Authorization: Bearer syntheticBearerTokenValue12345 and key sk_sim_ABC123456789XYZ",
			"nested": map[string]any{
				"api_key": "tism_sim_0000111122223333",
				"note":    "harmless field",
			},
		},
	}

	ev, err := norm.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}

	// Verify UTC timestamp normalization
	if ev.OccurredAt.Format(time.RFC3339) != "2026-06-01T08:15:00Z" {
		t.Fatalf("expected UTC 08:15:00Z, got %s", ev.OccurredAt.Format(time.RFC3339))
	}
	if ev.Actor != "dev-alice" || ev.Service != "order-router" || ev.Host != "trd-ord-01" {
		t.Fatalf("expected lowercased canonical identifiers, got actor=%q service=%q host=%q", ev.Actor, ev.Service, ev.Host)
	}

	// Verify sensitive fields and inline secrets never leak
	if ev.Attributes["fix_password"] != "[REDACTED]" {
		t.Fatalf("expected fix_password redacted, got %q", ev.Attributes["fix_password"])
	}
	if ev.Attributes["nested.api_key"] != "[REDACTED]" {
		t.Fatalf("expected nested.api_key redacted, got %q", ev.Attributes["nested.api_key"])
	}
	if strings.Contains(ev.Attributes["diff_summary"], "syntheticBearerTokenValue12345") ||
		strings.Contains(ev.Attributes["diff_summary"], "sk_sim_ABC123456789XYZ") {
		t.Fatalf("secret leaked in diff_summary: %q", ev.Attributes["diff_summary"])
	}
	if len(ev.RedactedFields) != 3 {
		t.Fatalf("expected 3 redaction records, got %d: %+v", len(ev.RedactedFields), ev.RedactedFields)
	}
	if ev.Attributes["nested.note"] != "harmless field" {
		t.Fatalf("non-sensitive field was unexpectedly altered: %q", ev.Attributes["nested.note"])
	}
}

func TestCanonicalHashIdenticalAcrossDuplicateDeliveries(t *testing.T) {
	t1 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 12, 5, 0, 0, time.UTC)
	n1, _ := NewNormalizer(testRedactionPolicy(), func() time.Time { return t1 })
	n2, _ := NewNormalizer(testRedactionPolicy(), func() time.Time { return t2 })

	raw1 := contracts.RawEvent{
		EventID:   "evt-dup-1",
		EventType: contracts.EventTypeAuthLog,
		Timestamp: "2026-06-01T10:00:00Z",
		Actor:     "ops-1",
		Service:   "order-router",
		Host:      "trd-ord-01",
		Action:    "login",
		Outcome:   "failure",
		SourceIP:  "10.10.5.5",
	}
	raw2 := raw1
	raw2.EventID = "evt-dup-1-replayed"

	e1, err := n1.Normalize(raw1)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := n2.Normalize(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if e1.CanonicalHash != e2.CanonicalHash {
		t.Fatalf("expected identical canonical hashes for duplicate delivery, got %s vs %s", e1.CanonicalHash, e2.CanonicalHash)
	}
}
