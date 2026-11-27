package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = "1.0.0"

	EventTypeAuthLog         EventType = "auth_log"
	EventTypeConfigDiff      EventType = "config_diff"
	EventTypeDeploymentAudit EventType = "deployment_audit"
	EventTypeOrderAudit      EventType = "order_audit"

	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"

	ContainmentModeSimulationOnly = "simulation_only"
)

var (
	ErrMissingConfig            = errors.New("missing configuration")
	ErrInvalidConfig            = errors.New("invalid configuration")
	ErrUnsupportedEventType     = errors.New("unsupported event type")
	ErrValidationFailed         = errors.New("event validation failed")
	ErrInvalidTimestamp         = errors.New("invalid RFC3339 timestamp")
	ErrLiveContainmentProhibited = errors.New("automatic or live containment is strictly prohibited in this lab monitor")
	ErrUnauthorizedReviewer     = errors.New("reviewer is not authorized by security policy")
	ErrSelfApprovalProhibited   = errors.New("self-approval is prohibited by separation-of-duties policy")
	ErrInvalidSuppression       = errors.New("invalid suppression rule")
	ErrAuditChainTampered       = errors.New("reviewer audit hash chain integrity check failed")
)

type EventType string

func (e EventType) IsValid() bool {
	switch e {
	case EventTypeAuthLog, EventTypeConfigDiff, EventTypeDeploymentAudit, EventTypeOrderAudit:
		return true
	default:
		return false
	}
}

type Severity string

func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

func (s Severity) IsValid() bool {
	return s.Rank() > 0
}

func MaxSeverity(a, b Severity) Severity {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

// RawEvent represents an incoming synthetic security event before normalization and redaction.
type RawEvent struct {
	EventID      string         `json:"event_id"`
	EventType    EventType      `json:"event_type"`
	Timestamp    string         `json:"timestamp"`
	Actor        string         `json:"actor"`
	Service      string         `json:"service"`
	Host         string         `json:"host"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome,omitempty"`
	SourceIP     string         `json:"source_ip,omitempty"`
	ChangeTicket string         `json:"change_ticket,omitempty"`
	SessionID    string         `json:"session_id,omitempty"`
	Payload      map[string]any `json:"payload,omitempty"`
}

// Validate checks canonical input contract invariants without mutating the event.
func (r RawEvent) Validate() error {
	if strings.TrimSpace(r.EventID) == "" {
		return fmt.Errorf("%w: event_id is required", ErrValidationFailed)
	}
	if !r.EventType.IsValid() {
		return fmt.Errorf("%w: %q", ErrUnsupportedEventType, r.EventType)
	}
	if strings.TrimSpace(r.Timestamp) == "" {
		return fmt.Errorf("%w: timestamp is required", ErrValidationFailed)
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Timestamp); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}
	if strings.TrimSpace(r.Actor) == "" {
		return fmt.Errorf("%w: actor is required", ErrValidationFailed)
	}
	if strings.TrimSpace(r.Service) == "" {
		return fmt.Errorf("%w: service is required", ErrValidationFailed)
	}
	if strings.TrimSpace(r.Host) == "" {
		return fmt.Errorf("%w: host is required", ErrValidationFailed)
	}
	if strings.TrimSpace(r.Action) == "" {
		return fmt.Errorf("%w: action is required", ErrValidationFailed)
	}
	if r.SourceIP != "" && net.ParseIP(r.SourceIP) == nil {
		return fmt.Errorf("%w: invalid source_ip %q", ErrValidationFailed, r.SourceIP)
	}
	// Type-specific required payload contracts
	switch r.EventType {
	case EventTypeConfigDiff:
		if r.Payload == nil || strings.TrimSpace(fmt.Sprint(r.Payload["config_path"])) == "" || r.Payload["config_path"] == nil {
			return fmt.Errorf("%w: config_diff requires payload.config_path", ErrValidationFailed)
		}
	case EventTypeDeploymentAudit:
		if r.Payload == nil || strings.TrimSpace(fmt.Sprint(r.Payload["artifact_sha256"])) == "" || r.Payload["artifact_sha256"] == nil {
			return fmt.Errorf("%w: deployment_audit requires payload.artifact_sha256", ErrValidationFailed)
		}
	case EventTypeOrderAudit:
		if r.Payload == nil || strings.TrimSpace(fmt.Sprint(r.Payload["order_id"])) == "" || r.Payload["order_id"] == nil {
			return fmt.Errorf("%w: order_audit requires payload.order_id", ErrValidationFailed)
		}
	}
	return nil
}

// RedactionRecord captures proof that a sensitive field was redacted without exposing its value.
type RedactionRecord struct {
	FieldPath         string `json:"field_path"`
	Reason            string `json:"reason"`
	ValueSHA256Prefix string `json:"value_sha256_prefix,omitempty"`
}

// NormalizedEvent is the canonical, redacted representation processed by detection and correlation.
type NormalizedEvent struct {
	EventID          string            `json:"event_id"`
	CanonicalHash    string            `json:"canonical_hash"`
	SchemaVersion    string            `json:"schema_version"`
	EventType        EventType         `json:"event_type"`
	OccurredAt       time.Time         `json:"occurred_at"`
	OccurredAtUnixMs int64             `json:"occurred_at_unix_ms"`
	IngestedAt       time.Time         `json:"ingested_at"`
	Actor            string            `json:"actor"`
	Service          string            `json:"service"`
	Host             string            `json:"host"`
	Action           string            `json:"action"`
	Outcome          string            `json:"outcome"`
	SourceIP         string            `json:"source_ip,omitempty"`
	ChangeTicket     string            `json:"change_ticket,omitempty"`
	SessionID        string            `json:"session_id,omitempty"`
	RedactedFields   []RedactionRecord `json:"redacted_fields"`
	Attributes       map[string]string `json:"attributes"`
	PayloadRedacted  map[string]any    `json:"payload_redacted"`
}

// Alert is a security finding traced to one or more source events.
type Alert struct {
	AlertID           string            `json:"alert_id"`
	RuleID            string            `json:"rule_id"`
	RuleTitle         string            `json:"rule_title"`
	Category          string            `json:"category"`
	Severity          Severity          `json:"severity"`
	OccurredAt        time.Time         `json:"occurred_at"`
	Actor             string            `json:"actor"`
	Service           string            `json:"service"`
	Host              string            `json:"host"`
	Summary           string            `json:"summary"`
	SourceEventIDs    []string          `json:"source_event_ids"`
	Suppressed        bool              `json:"suppressed"`
	SuppressionID     string            `json:"suppression_id,omitempty"`
	SuppressionReason string            `json:"suppression_reason,omitempty"`
	Evidence          map[string]string `json:"evidence"`
	Tags              []string          `json:"tags,omitempty"`
}

// CaseTimelineEntry records an ordered alert or event milestone inside a correlated case.
type CaseTimelineEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	AlertID        string    `json:"alert_id"`
	RuleID         string    `json:"rule_id"`
	Severity       Severity  `json:"severity"`
	Summary        string    `json:"summary"`
	SourceEventIDs []string  `json:"source_event_ids"`
}

// Case correlates related non-suppressed alerts into an evidence-backed investigation unit.
type Case struct {
	CaseID             string              `json:"case_id"`
	Title              string              `json:"title"`
	Severity           Severity            `json:"severity"`
	Status             string              `json:"status"`
	FirstSeen          time.Time           `json:"first_seen"`
	LastSeen           time.Time           `json:"last_seen"`
	PrimaryActor       string              `json:"primary_actor"`
	AffectedServices   []string            `json:"affected_services"`
	AffectedHosts      []string            `json:"affected_hosts"`
	AlertIDs           []string            `json:"alert_ids"`
	SourceEventIDs     []string            `json:"source_event_ids"`
	CorrelationReasons []string            `json:"correlation_reasons"`
	Timeline           []CaseTimelineEntry `json:"timeline"`
	RecommendedActions []string            `json:"recommended_actions"`
}

// TelemetryGap records missing telemetry detected from an expected log source.
type TelemetryGap struct {
	Source         EventType `json:"source"`
	Reason         string    `json:"reason"`
	GapStart       time.Time `json:"gap_start"`
	GapEnd         time.Time `json:"gap_end"`
	GapDurationSec int64     `json:"gap_duration_seconds"`
}

// DiagnosticMetrics tracks pipeline counts and health indicators.
type DiagnosticMetrics struct {
	EventsIngested        int `json:"events_ingested"`
	EventsNormalized      int `json:"events_normalized"`
	EventsDeduplicated    int `json:"events_deduplicated"`
	EventsInvalid         int `json:"events_invalid"`
	FieldsRedacted        int `json:"fields_redacted"`
	TelemetryGapsDetected int `json:"telemetry_gaps_detected"`
	AlertsTotal           int `json:"alerts_total"`
	AlertsActive          int `json:"alerts_active"`
	AlertsSuppressed      int `json:"alerts_suppressed"`
	CasesCreated          int `json:"cases_created"`
	ProposalsCreated      int `json:"proposals_created"`
}

// ContainmentProposal describes a simulated-only containment action requiring reviewer approval.
type ContainmentProposal struct {
	ProposalID        string             `json:"proposal_id"`
	CaseID            string             `json:"case_id"`
	ActionType        string             `json:"action_type"`
	Target            string             `json:"target"`
	ExecutionMode     string             `json:"execution_mode"`
	LiveExecuted      bool               `json:"live_executed"`
	Severity          Severity           `json:"severity"`
	RequestedBy       string             `json:"requested_by"`
	RequiredApprovals int                `json:"required_approvals"`
	Status            string             `json:"status"`
	Approvals         []ReviewerApproval `json:"approvals"`
	BlastRadius       []string           `json:"blast_radius"`
	RollbackPlan      string             `json:"rollback_plan"`
	SimulatedDiff     map[string]string  `json:"simulated_diff"`
	CreatedAt         time.Time          `json:"created_at"`
}

// ReviewerApproval records an explicit human review decision on a containment proposal.
type ReviewerApproval struct {
	Reviewer  string    `json:"reviewer"`
	Decision  string    `json:"decision"` // "approve" or "reject"
	Rationale string    `json:"rationale"`
	Timestamp time.Time `json:"timestamp"`
}

// AuditRecord forms a tamper-evident hash chain for reviewer and suppression decisions.
type AuditRecord struct {
	SequenceNum int64     `json:"sequence_num"`
	RecordID    string    `json:"record_id"`
	Timestamp   time.Time `json:"timestamp"`
	Reviewer    string    `json:"reviewer"`
	Action      string    `json:"action"`
	TargetID    string    `json:"target_id"`
	Decision    string    `json:"decision"`
	Rationale   string    `json:"rationale"`
	PrevHash    string    `json:"prev_hash"`
	RecordHash  string    `json:"record_hash"`
}

// MonitorConfig defines runtime pipeline settings.
type MonitorConfig struct {
	SchemaVersion           string      `json:"schema_version"`
	Environment             string      `json:"environment"`
	DeterministicSeed       int64       `json:"deterministic_seed"`
	RulesDir                string      `json:"rules_dir"`
	PolicyPath              string      `json:"policy_path"`
	RedactionPolicyPath     string      `json:"redaction_policy_path"`
	ContainmentMode         string      `json:"containment_mode"`
	LiveContainmentEnabled  bool        `json:"live_containment_enabled"`
	CorrelationWindowSec    int64       `json:"correlation_window_seconds"`
	TelemetryGapThresholdSec int64      `json:"telemetry_gap_threshold_seconds"`
	ExpectedSources         []EventType `json:"expected_sources"`
	DeduplicationEnabled    bool        `json:"deduplication_enabled"`
	OtelServiceName         string      `json:"otel_service_name"`
	OtelServiceVersion      string      `json:"otel_service_version"`
}

func (c MonitorConfig) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %q", ErrInvalidConfig, c.SchemaVersion)
	}
	if c.LiveContainmentEnabled || c.ContainmentMode != ContainmentModeSimulationOnly {
		return fmt.Errorf("%w: containment_mode=%q live_containment_enabled=%v", ErrLiveContainmentProhibited, c.ContainmentMode, c.LiveContainmentEnabled)
	}
	if c.CorrelationWindowSec <= 0 {
		return fmt.Errorf("%w: correlation_window_seconds must be > 0", ErrInvalidConfig)
	}
	if c.TelemetryGapThresholdSec <= 0 {
		return fmt.Errorf("%w: telemetry_gap_threshold_seconds must be > 0", ErrInvalidConfig)
	}
	for _, src := range c.ExpectedSources {
		if !src.IsValid() {
			return fmt.Errorf("%w: expected_sources contains invalid type %q", ErrInvalidConfig, src)
		}
	}
	return nil
}

type ApprovedChangeTicket struct {
	TicketID               string   `json:"ticket_id"`
	Actor                  string   `json:"actor"`
	Service                string   `json:"service"`
	AllowedPaths           []string `json:"allowed_paths"`
	ExpectedArtifactSHA256 string   `json:"expected_artifact_sha256"`
	WindowStart            string   `json:"window_start"`
	WindowEnd              string   `json:"window_end"`
	ApprovedBy             string   `json:"approved_by"`
}

type BusinessHours struct {
	StartHour int `json:"start_hour"`
	EndHour   int `json:"end_hour"`
}

type SuppressionRule struct {
	SuppressionID string `json:"suppression_id"`
	RuleID        string `json:"rule_id"`
	Actor         string `json:"actor"`
	Service       string `json:"service"`
	TicketID      string `json:"ticket_id"`
	Reason        string `json:"reason"`
	ApprovedBy    string `json:"approved_by"`
	ExpiresAt     string `json:"expires_at"`
}

type SecurityPolicy struct {
	SchemaVersion           string                 `json:"schema_version"`
	DefaultEffect           string                 `json:"default_effect"`
	AllowedDeploymentActors []string               `json:"allowed_deployment_actors"`
	AllowedConfigEditors    []string               `json:"allowed_config_editors"`
	ApprovedChangeTickets   []ApprovedChangeTicket `json:"approved_change_tickets"`
	PrivilegedRoles         []string               `json:"privileged_roles"`
	ServiceAccounts         []string               `json:"service_accounts"`
	TrustedCIDRs            []string               `json:"trusted_cidrs"`
	AllowedBusinessHoursUTC BusinessHours          `json:"allowed_business_hours_utc"`
	BruteForceThreshold     int                    `json:"brute_force_threshold"`
	BruteForceWindowSec     int64                  `json:"brute_force_window_seconds"`
	OrderBurstThreshold     int                    `json:"order_burst_threshold"`
	OrderBurstWindowSec     int64                  `json:"order_burst_window_seconds"`
	ProtectedConfigPaths    []string               `json:"protected_config_paths"`
	AuthorizedReviewers     []string               `json:"authorized_reviewers"`
	DualControlSeverities   []Severity             `json:"dual_control_severities"`
	Suppressions            []SuppressionRule      `json:"suppressions"`
}

func (p SecurityPolicy) Validate() error {
	if strings.ToLower(p.DefaultEffect) != "deny" {
		return fmt.Errorf("%w: security policy must use deny-by-default (default_effect=deny)", ErrInvalidConfig)
	}
	if p.BruteForceThreshold <= 0 || p.BruteForceWindowSec <= 0 {
		return fmt.Errorf("%w: brute_force threshold/window must be positive", ErrInvalidConfig)
	}
	if p.OrderBurstThreshold <= 0 || p.OrderBurstWindowSec <= 0 {
		return fmt.Errorf("%w: order_burst threshold/window must be positive", ErrInvalidConfig)
	}
	for _, cidr := range p.TrustedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, cidr, err)
		}
	}
	for _, s := range p.Suppressions {
		if err := ValidateSuppressionRule(s, p.AuthorizedReviewers); err != nil {
			return err
		}
	}
	return nil
}

// ValidateSuppressionRule enforces tight guardrails on false-positive suppressions:
// no wildcards, mandatory ticket/reason/expiration, and authorized reviewer sign-off.
func ValidateSuppressionRule(s SuppressionRule, authorizedReviewers []string) error {
	if strings.TrimSpace(s.SuppressionID) == "" {
		return fmt.Errorf("%w: suppression_id is required", ErrInvalidSuppression)
	}
	if strings.TrimSpace(s.RuleID) == "" || s.RuleID == "*" {
		return fmt.Errorf("%w: wildcard or empty rule_id is prohibited", ErrInvalidSuppression)
	}
	if strings.TrimSpace(s.Actor) == "" || s.Actor == "*" {
		return fmt.Errorf("%w: wildcard or empty actor is prohibited", ErrInvalidSuppression)
	}
	if strings.TrimSpace(s.Service) == "" || s.Service == "*" {
		return fmt.Errorf("%w: wildcard or empty service is prohibited", ErrInvalidSuppression)
	}
	if strings.TrimSpace(s.TicketID) == "" || strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("%w: ticket_id and reason are mandatory", ErrInvalidSuppression)
	}
	if _, err := time.Parse(time.RFC3339, s.ExpiresAt); err != nil {
		return fmt.Errorf("%w: invalid expires_at %q: %v", ErrInvalidSuppression, s.ExpiresAt, err)
	}
	authorized := false
	for _, r := range authorizedReviewers {
		if r == s.ApprovedBy {
			authorized = true
			break
		}
	}
	if !authorized {
		return fmt.Errorf("%w: suppression %s approved_by %q is not an authorized reviewer", ErrUnauthorizedReviewer, s.SuppressionID, s.ApprovedBy)
	}
	return nil
}

type RedactionPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type RedactionPolicy struct {
	SchemaVersion             string             `json:"schema_version"`
	ReplacementToken          string             `json:"replacement_token"`
	PreserveSHA256Fingerprint bool               `json:"preserve_sha256_fingerprint"`
	SensitiveFieldNames       []string           `json:"sensitive_field_names"`
	ValuePatterns             []RedactionPattern `json:"value_patterns"`
}

// ValidationErrorRecord logs an input event rejected during schema validation.
type ValidationErrorRecord struct {
	LineNumber int    `json:"line_number"`
	EventID    string `json:"event_id,omitempty"`
	Error      string `json:"error"`
}

// RunMetadata records environment and version info for reproducibility.
type RunMetadata struct {
	RunID             string `json:"run_id"`
	SchemaVersion     string `json:"schema_version"`
	Environment       string `json:"environment"`
	DeterministicSeed int64  `json:"deterministic_seed"`
	ContainmentMode   string `json:"containment_mode"`
	LiveContainment   bool   `json:"live_containment"`
	GoVersion         string `json:"go_version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	InputPath         string `json:"input_path,omitempty"`
	InputSHA256       string `json:"input_sha256,omitempty"`
}

// RunReport is the canonical end-to-end output contract for a monitoring run.
type RunReport struct {
	Metadata             RunMetadata             `json:"metadata"`
	Metrics              DiagnosticMetrics       `json:"metrics"`
	TelemetryGaps        []TelemetryGap          `json:"telemetry_gaps"`
	ValidationErrors     []ValidationErrorRecord `json:"validation_errors"`
	Alerts               []Alert                 `json:"alerts"`
	Cases                []Case                  `json:"cases"`
	ContainmentProposals []ContainmentProposal   `json:"containment_proposals"`
	ReviewerAuditLog     []AuditRecord           `json:"reviewer_audit_log"`
}

// EvaluationReport summarizes synthetic detection recall, precision, and false-positive counts.
type EvaluationReport struct {
	Metadata              RunMetadata `json:"metadata"`
	ExpectedAlertCount    int         `json:"expected_alert_count"`
	ObservedActiveAlerts  int         `json:"observed_active_alerts"`
	SuppressedAlerts      int         `json:"suppressed_alerts"`
	TruePositives         int         `json:"true_positives"`
	FalsePositives        int         `json:"false_positives"`
	FalseNegatives        int         `json:"false_negatives"`
	Recall                float64     `json:"recall"`
	Precision             float64     `json:"precision"`
	F1Score               float64     `json:"f1_score"`
	AllAlertsTraced       bool        `json:"all_alerts_traced"`
	LiveContainmentCount  int         `json:"live_containment_count"`
	ExpectedCaseCount     int         `json:"expected_case_count"`
	ObservedCaseCount     int         `json:"observed_case_count"`
	MissingExpectedAlerts []string    `json:"missing_expected_alerts"`
	UnexpectedAlerts      []string    `json:"unexpected_alerts"`
}

// LoadJSONFile reads and decodes a JSON configuration file, returning ErrMissingConfig if absent.
func LoadJSONFile[T any](path string) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, fmt.Errorf("%w: %s", ErrMissingConfig, path)
		}
		return zero, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &zero); err != nil {
		return zero, fmt.Errorf("%w: parse %s: %v", ErrInvalidConfig, path, err)
	}
	return zero, nil
}

// StableID deterministically computes a prefixed hex identifier from canonical input parts.
func StableID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s-%s", prefix, sum[:12])
}

// SortedUnique returns a deterministic sorted deduplicated slice of strings.
func SortedUnique(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
