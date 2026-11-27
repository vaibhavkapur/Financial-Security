package contracts

import (
	"errors"
	"testing"
)

func TestRawEventValidation(t *testing.T) {
	validAuth := RawEvent{
		EventID:   "evt-001",
		EventType: EventTypeAuthLog,
		Timestamp: "2026-06-01T10:05:00Z",
		Actor:     "trader-ops-1",
		Service:   "order-router",
		Host:      "trd-ord-01",
		Action:    "login",
		Outcome:   "success",
		SourceIP:  "10.10.1.5",
	}
	if err := validAuth.Validate(); err != nil {
		t.Fatalf("expected valid auth event, got error: %v", err)
	}

	cases := []struct {
		name    string
		ev      RawEvent
		wantErr error
	}{
		{
			name:    "unsupported event type",
			ev:      RawEvent{EventID: "e1", EventType: "dns_query", Timestamp: "2026-06-01T10:00:00Z", Actor: "a", Service: "s", Host: "h", Action: "x"},
			wantErr: ErrUnsupportedEventType,
		},
		{
			name:    "invalid timestamp",
			ev:      RawEvent{EventID: "e2", EventType: EventTypeAuthLog, Timestamp: "not-a-date", Actor: "a", Service: "s", Host: "h", Action: "x"},
			wantErr: ErrInvalidTimestamp,
		},
		{
			name:    "invalid IP",
			ev:      RawEvent{EventID: "e3", EventType: EventTypeAuthLog, Timestamp: "2026-06-01T10:00:00Z", Actor: "a", Service: "s", Host: "h", Action: "x", SourceIP: "999.999.1.1"},
			wantErr: ErrValidationFailed,
		},
		{
			name:    "config diff missing config_path",
			ev:      RawEvent{EventID: "e4", EventType: EventTypeConfigDiff, Timestamp: "2026-06-01T10:00:00Z", Actor: "a", Service: "s", Host: "h", Action: "edit", Payload: map[string]any{}},
			wantErr: ErrValidationFailed,
		},
		{
			name:    "deployment missing artifact_sha256",
			ev:      RawEvent{EventID: "e5", EventType: EventTypeDeploymentAudit, Timestamp: "2026-06-01T10:00:00Z", Actor: "a", Service: "s", Host: "h", Action: "deploy_release", Payload: map[string]any{}},
			wantErr: ErrValidationFailed,
		},
		{
			name:    "order audit missing order_id",
			ev:      RawEvent{EventID: "e6", EventType: EventTypeOrderAudit, Timestamp: "2026-06-01T10:00:00Z", Actor: "a", Service: "s", Host: "h", Action: "submit_order", Payload: map[string]any{}},
			wantErr: ErrValidationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ev.Validate()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestMonitorConfigProhibitsLiveContainment(t *testing.T) {
	cfg := MonitorConfig{
		SchemaVersion:            SchemaVersion,
		ContainmentMode:          "live",
		LiveContainmentEnabled:   true,
		CorrelationWindowSec:     900,
		TelemetryGapThresholdSec: 300,
	}
	if err := cfg.Validate(); !errors.Is(err, ErrLiveContainmentProhibited) {
		t.Fatalf("expected ErrLiveContainmentProhibited, got %v", err)
	}
}

func TestSuppressionRuleGuardrails(t *testing.T) {
	reviewers := []string{"sec-reviewer-alice"}
	badWildcard := SuppressionRule{
		SuppressionID: "SUP-BAD-1",
		RuleID:        "TISM-SIGMA-001",
		Actor:         "*",
		Service:       "order-router",
		TicketID:      "INC-1",
		Reason:        "too broad",
		ApprovedBy:    "sec-reviewer-alice",
		ExpiresAt:     "2026-06-05T00:00:00Z",
	}
	if err := ValidateSuppressionRule(badWildcard, reviewers); !errors.Is(err, ErrInvalidSuppression) {
		t.Fatalf("expected ErrInvalidSuppression for wildcard actor, got %v", err)
	}

	unauth := badWildcard
	unauth.Actor = "ops-user"
	unauth.ApprovedBy = "random-user"
	if err := ValidateSuppressionRule(unauth, reviewers); !errors.Is(err, ErrUnauthorizedReviewer) {
		t.Fatalf("expected ErrUnauthorizedReviewer, got %v", err)
	}
}

func TestStableIDDeterminism(t *testing.T) {
	id1 := StableID("ALT", "TISM-SIGMA-001", "evt-001")
	id2 := StableID("ALT", "TISM-SIGMA-001", "evt-001")
	id3 := StableID("ALT", "TISM-SIGMA-001", "evt-002")
	if id1 != id2 {
		t.Fatalf("expected identical stable IDs, got %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("expected different stable IDs for distinct inputs")
	}
}
