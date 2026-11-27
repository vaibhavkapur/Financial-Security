package detector

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/rules"
)

// Engine is a pure domain detector isolated from I/O.
type Engine struct {
	policyEval   *PolicyEvaluator
	policy       contracts.SecurityPolicy
	sigmaRules   []rules.SigmaRule
	suppressions []parsedSuppression
}

type parsedSuppression struct {
	rule      contracts.SuppressionRule
	expiresAt time.Time
}

// SuppressionAuditEvent records when a suppression rule matched an alert (for reviewer audit trail).
type SuppressionAuditEvent struct {
	AlertID       string
	RuleID        string
	SuppressionID string
	ApprovedBy    string
	TicketID      string
	Reason        string
	Timestamp     time.Time
}

// DetectionResult bundles generated alerts, telemetry gaps, and suppression audit hooks.
type DetectionResult struct {
	EnrichedEvents    []contracts.NormalizedEvent
	Alerts            []contracts.Alert
	TelemetryGaps     []contracts.TelemetryGap
	SuppressionAudits []SuppressionAuditEvent
}

func NewEngine(policy contracts.SecurityPolicy, sigmaRules []rules.SigmaRule) (*Engine, error) {
	pe, err := NewPolicyEvaluator(policy)
	if err != nil {
		return nil, err
	}
	sups := make([]parsedSuppression, 0, len(policy.Suppressions))
	for _, s := range policy.Suppressions {
		if err := contracts.ValidateSuppressionRule(s, policy.AuthorizedReviewers); err != nil {
			return nil, err
		}
		exp, _ := time.Parse(time.RFC3339, s.ExpiresAt)
		sups = append(sups, parsedSuppression{rule: s, expiresAt: exp.UTC()})
	}
	copiedRules := make([]rules.SigmaRule, len(sigmaRules))
	copy(copiedRules, sigmaRules)
	sort.Slice(copiedRules, func(i, j int) bool { return copiedRules[i].ID < copiedRules[j].ID })

	return &Engine{
		policyEval:   pe,
		policy:       policy,
		sigmaRules:   copiedRules,
		suppressions: sups,
	}, nil
}

// Evaluate processes a slice of NormalizedEvents deterministically, returning alerts, gaps, and suppression audits.
func (e *Engine) Evaluate(events []contracts.NormalizedEvent, expectedSources []contracts.EventType, gapThresholdSec int64) DetectionResult {
	// Sort chronologically with deterministic tie-breaker on EventID
	sorted := make([]contracts.NormalizedEvent, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].OccurredAt.Equal(sorted[j].OccurredAt) {
			return sorted[i].EventID < sorted[j].EventID
		}
		return sorted[i].OccurredAt.Before(sorted[j].OccurredAt)
	})

	enriched := make([]contracts.NormalizedEvent, 0, len(sorted))
	alerts := make([]contracts.Alert, 0)

	// 1. Policy enrichment + stateless Sigma rules
	for _, ev := range sorted {
		enr := e.policyEval.EnrichEvent(ev)
		enriched = append(enriched, enr)
		for i := range e.sigmaRules {
			rule := &e.sigmaRules[i]
			if rule.Match(enr) {
				alerts = append(alerts, buildSigmaAlert(*rule, enr))
			}
		}
	}

	// 2. Stateful behavioral anomaly detection (brute-force bursts & order bursts)
	alerts = append(alerts, e.detectAuthBruteForce(enriched)...)
	alerts = append(alerts, e.detectOrderVelocityBurst(enriched)...)

	// 3. Telemetry gap detection (missing sources or silent stretches)
	gaps, gapAlerts := e.detectTelemetryGaps(enriched, expectedSources, gapThresholdSec)
	alerts = append(alerts, gapAlerts...)

	// 4. Deterministic sorting of alerts before suppression evaluation
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].OccurredAt.Equal(alerts[j].OccurredAt) {
			return alerts[i].AlertID < alerts[j].AlertID
		}
		return alerts[i].OccurredAt.Before(alerts[j].OccurredAt)
	})

	// 5. Auditable, time-bounded false-positive suppression (fail-closed when expired)
	supAudits := make([]SuppressionAuditEvent, 0)
	for i := range alerts {
		if sup, ok := e.findActiveSuppression(alerts[i]); ok {
			alerts[i].Suppressed = true
			alerts[i].SuppressionID = sup.rule.SuppressionID
			alerts[i].SuppressionReason = sup.rule.Reason
			alerts[i].Evidence["suppression_ticket"] = sup.rule.TicketID
			alerts[i].Evidence["suppression_approved_by"] = sup.rule.ApprovedBy
			supAudits = append(supAudits, SuppressionAuditEvent{
				AlertID:       alerts[i].AlertID,
				RuleID:        alerts[i].RuleID,
				SuppressionID: sup.rule.SuppressionID,
				ApprovedBy:    sup.rule.ApprovedBy,
				TicketID:      sup.rule.TicketID,
				Reason:        sup.rule.Reason,
				Timestamp:     alerts[i].OccurredAt,
			})
		}
	}

	return DetectionResult{
		EnrichedEvents:    enriched,
		Alerts:            alerts,
		TelemetryGaps:     gaps,
		SuppressionAudits: supAudits,
	}
}

func buildSigmaAlert(rule rules.SigmaRule, ev contracts.NormalizedEvent) contracts.Alert {
	evidence := map[string]string{
		"event_type":             string(ev.EventType),
		"action":                 ev.Action,
		"outcome":                ev.Outcome,
		"policy_decision_reason": ev.Attributes["policy_decision_reason"],
	}
	if ev.SourceIP != "" {
		evidence["source_ip"] = ev.SourceIP
	}
	if ev.ChangeTicket != "" {
		evidence["change_ticket"] = ev.ChangeTicket
	}
	if ev.SessionID != "" {
		evidence["session_id"] = ev.SessionID
	}
	if p, ok := ev.Attributes["config_path"]; ok && p != "" {
		evidence["config_path"] = p
	}
	if sha, ok := ev.Attributes["artifact_sha256"]; ok && sha != "" {
		evidence["artifact_sha256"] = sha
	}
	if role, ok := ev.Attributes["target_role"]; ok && role != "" {
		evidence["target_role"] = role
	}
	if oid, ok := ev.Attributes["order_id"]; ok && oid != "" {
		evidence["order_id"] = oid
	}

	summary := fmt.Sprintf("%s by actor %s on %s (%s)", rule.Title, ev.Actor, ev.Service, ev.Attributes["policy_decision_reason"])
	return contracts.Alert{
		AlertID:        contracts.StableID("ALT", rule.ID, ev.EventID),
		RuleID:         rule.ID,
		RuleTitle:      rule.Title,
		Category:       string(ev.EventType),
		Severity:       rule.Level,
		OccurredAt:     ev.OccurredAt,
		Actor:          ev.Actor,
		Service:        ev.Service,
		Host:           ev.Host,
		Summary:        summary,
		SourceEventIDs: []string{ev.EventID},
		Evidence:       evidence,
		Tags:           append([]string{}, rule.Tags...),
	}
}

func (e *Engine) detectAuthBruteForce(events []contracts.NormalizedEvent) []contracts.Alert {
	window := time.Duration(e.policy.BruteForceWindowSec) * time.Second
	threshold := e.policy.BruteForceThreshold

	byActor := make(map[string][]contracts.NormalizedEvent)
	for _, ev := range events {
		if ev.EventType == contracts.EventTypeAuthLog && ev.Action == "login" && ev.Outcome == "failure" {
			byActor[ev.Actor] = append(byActor[ev.Actor], ev)
		}
	}

	actors := make([]string, 0, len(byActor))
	for a := range byActor {
		actors = append(actors, a)
	}
	sort.Strings(actors)

	alerts := make([]contracts.Alert, 0)
	for _, actor := range actors {
		evs := byActor[actor]
		start := 0
		firedWindowEnd := time.Time{}
		for end := 0; end < len(evs); end++ {
			for evs[end].OccurredAt.Sub(evs[start].OccurredAt) > window {
				start++
			}
			count := end - start + 1
			if count >= threshold && (firedWindowEnd.IsZero() || evs[start].OccurredAt.After(firedWindowEnd)) {
				slice := evs[start : end+1]
				ids := make([]string, len(slice))
				for i, se := range slice {
					ids[i] = se.EventID
				}
				last := slice[len(slice)-1]
				alerts = append(alerts, contracts.Alert{
					AlertID:        contracts.StableID("ALT", "TISM-STATE-001", actor, strings.Join(ids, ",")),
					RuleID:         "TISM-STATE-001",
					RuleTitle:      "Authentication Brute-Force Failure Burst",
					Category:       string(contracts.EventTypeAuthLog),
					Severity:       contracts.SeverityHigh,
					OccurredAt:     last.OccurredAt,
					Actor:          actor,
					Service:        last.Service,
					Host:           last.Host,
					Summary:        fmt.Sprintf("%d failed logins for actor %s within %ds", count, actor, e.policy.BruteForceWindowSec),
					SourceEventIDs: ids,
					Evidence: map[string]string{
						"failure_count":  fmt.Sprintf("%d", count),
						"window_seconds": fmt.Sprintf("%d", e.policy.BruteForceWindowSec),
						"source_ip":      last.SourceIP,
					},
					Tags: []string{"attack.credential_access", "trading.auth_burst"},
				})
				firedWindowEnd = last.OccurredAt
			}
		}
	}
	return alerts
}

func (e *Engine) detectOrderVelocityBurst(events []contracts.NormalizedEvent) []contracts.Alert {
	window := time.Duration(e.policy.OrderBurstWindowSec) * time.Second
	threshold := e.policy.OrderBurstThreshold

	byKey := make(map[string][]contracts.NormalizedEvent)
	for _, ev := range events {
		if ev.EventType == contracts.EventTypeOrderAudit && ev.Action == "submit_order" {
			key := ev.Actor + "|" + ev.Service
			byKey[key] = append(byKey[key], ev)
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	alerts := make([]contracts.Alert, 0)
	for _, key := range keys {
		evs := byKey[key]
		start := 0
		firedWindowEnd := time.Time{}
		for end := 0; end < len(evs); end++ {
			for evs[end].OccurredAt.Sub(evs[start].OccurredAt) > window {
				start++
			}
			count := end - start + 1
			if count >= threshold && (firedWindowEnd.IsZero() || evs[start].OccurredAt.After(firedWindowEnd)) {
				slice := evs[start : end+1]
				ids := make([]string, len(slice))
				for i, se := range slice {
					ids[i] = se.EventID
				}
				last := slice[len(slice)-1]
				alerts = append(alerts, contracts.Alert{
					AlertID:        contracts.StableID("ALT", "TISM-STATE-002", key, strings.Join(ids, ",")),
					RuleID:         "TISM-STATE-002",
					RuleTitle:      "Anomalous Order Submission Velocity Burst",
					Category:       string(contracts.EventTypeOrderAudit),
					Severity:       contracts.SeverityHigh,
					OccurredAt:     last.OccurredAt,
					Actor:          last.Actor,
					Service:        last.Service,
					Host:           last.Host,
					Summary:        fmt.Sprintf("%d order submissions by %s on %s within %ds", count, last.Actor, last.Service, e.policy.OrderBurstWindowSec),
					SourceEventIDs: ids,
					Evidence: map[string]string{
						"order_count":    fmt.Sprintf("%d", count),
						"window_seconds": fmt.Sprintf("%d", e.policy.OrderBurstWindowSec),
					},
					Tags: []string{"attack.impact", "trading.order_velocity"},
				})
				firedWindowEnd = last.OccurredAt
			}
		}
	}
	return alerts
}

func (e *Engine) detectTelemetryGaps(events []contracts.NormalizedEvent, expectedSources []contracts.EventType, gapThresholdSec int64) ([]contracts.TelemetryGap, []contracts.Alert) {
	if len(events) == 0 || len(expectedSources) == 0 || gapThresholdSec <= 0 {
		return []contracts.TelemetryGap{}, []contracts.Alert{}
	}
	globalStart := events[0].OccurredAt
	globalEnd := events[len(events)-1].OccurredAt
	firstID := events[0].EventID
	lastID := events[len(events)-1].EventID
	threshold := time.Duration(gapThresholdSec) * time.Second

	bySource := make(map[contracts.EventType][]contracts.NormalizedEvent)
	for _, ev := range events {
		bySource[ev.EventType] = append(bySource[ev.EventType], ev)
	}

	sources := make([]contracts.EventType, len(expectedSources))
	copy(sources, expectedSources)
	sort.Slice(sources, func(i, j int) bool { return sources[i] < sources[j] })

	gaps := make([]contracts.TelemetryGap, 0)
	alerts := make([]contracts.Alert, 0)

	for _, src := range sources {
		evs := bySource[src]
		if len(evs) == 0 {
			dur := int64(globalEnd.Sub(globalStart).Seconds())
			gap := contracts.TelemetryGap{
				Source:         src,
				Reason:         "source_completely_missing",
				GapStart:       globalStart,
				GapEnd:         globalEnd,
				GapDurationSec: dur,
			}
			gaps = append(gaps, gap)
			traceIDs := contracts.SortedUnique([]string{firstID, lastID})
			alerts = append(alerts, contracts.Alert{
				AlertID:        contracts.StableID("ALT", "TISM-HEALTH-001", string(src), "missing", strings.Join(traceIDs, ",")),
				RuleID:         "TISM-HEALTH-001",
				RuleTitle:      "Missing Telemetry Source Coverage",
				Category:       "telemetry_health",
				Severity:       contracts.SeverityMedium,
				OccurredAt:     globalEnd,
				Actor:          "telemetry-monitor",
				Service:        string(src),
				Host:           "telemetry-pipeline",
				Summary:        fmt.Sprintf("Expected telemetry source %s emitted 0 events during monitoring window", src),
				SourceEventIDs: traceIDs,
				Evidence: map[string]string{
					"missing_source":       string(src),
					"gap_reason":           gap.Reason,
					"gap_duration_seconds": fmt.Sprintf("%d", dur),
				},
				Tags: []string{"telemetry.coverage", "resilience.missing_logs"},
			})
			continue
		}
		for i := 1; i < len(evs); i++ {
			delta := evs[i].OccurredAt.Sub(evs[i-1].OccurredAt)
			if delta > threshold {
				dur := int64(delta.Seconds())
				gap := contracts.TelemetryGap{
					Source:         src,
					Reason:         "inter_event_silence_exceeded",
					GapStart:       evs[i-1].OccurredAt,
					GapEnd:         evs[i].OccurredAt,
					GapDurationSec: dur,
				}
				gaps = append(gaps, gap)
				traceIDs := []string{evs[i-1].EventID, evs[i].EventID}
				alerts = append(alerts, contracts.Alert{
					AlertID:        contracts.StableID("ALT", "TISM-HEALTH-001", string(src), evs[i-1].EventID, evs[i].EventID),
					RuleID:         "TISM-HEALTH-001",
					RuleTitle:      "Telemetry Stream Silence Gap Detected",
					Category:       "telemetry_health",
					Severity:       contracts.SeverityMedium,
					OccurredAt:     evs[i].OccurredAt,
					Actor:          "telemetry-monitor",
					Service:        string(src),
					Host:           "telemetry-pipeline",
					Summary:        fmt.Sprintf("Telemetry source %s had a %ds silence gap exceeding %ds threshold", src, dur, gapThresholdSec),
					SourceEventIDs: traceIDs,
					Evidence: map[string]string{
						"missing_source":       string(src),
						"gap_reason":           gap.Reason,
						"gap_duration_seconds": fmt.Sprintf("%d", dur),
						"threshold_seconds":    fmt.Sprintf("%d", gapThresholdSec),
					},
					Tags: []string{"telemetry.coverage", "resilience.gap"},
				})
			}
		}
	}
	return gaps, alerts
}

func (e *Engine) findActiveSuppression(a contracts.Alert) (parsedSuppression, bool) {
	for _, s := range e.suppressions {
		if strings.EqualFold(s.rule.RuleID, a.RuleID) &&
			strings.EqualFold(s.rule.Actor, a.Actor) &&
			strings.EqualFold(s.rule.Service, a.Service) {
			// Time-bounded fail-closed check
			if !a.OccurredAt.After(s.expiresAt) {
				return s, true
			}
		}
	}
	return parsedSuppression{}, false
}
