package correlator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

// Correlator groups active security alerts into evidence-backed cases with stable IDs.
type Correlator struct {
	window time.Duration
}

func NewCorrelator(windowSeconds int64) *Correlator {
	if windowSeconds <= 0 {
		windowSeconds = 900
	}
	return &Correlator{window: time.Duration(windowSeconds) * time.Second}
}

// Correlate builds deterministic Case records from non-suppressed alerts.
func (c *Correlator) Correlate(alerts []contracts.Alert) []contracts.Case {
	active := make([]contracts.Alert, 0, len(alerts))
	for _, a := range alerts {
		if !a.Suppressed {
			active = append(active, a)
		}
	}
	if len(active) == 0 {
		return []contracts.Case{}
	}

	sort.Slice(active, func(i, j int) bool {
		if active[i].OccurredAt.Equal(active[j].OccurredAt) {
			return active[i].AlertID < active[j].AlertID
		}
		return active[i].OccurredAt.Before(active[j].OccurredAt)
	})

	// Union-Find clustering for alerts sharing actor, host+service, session, or change_ticket within window
	parent := make([]int, len(active))
	reasons := make([][]string, len(active))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(i, j int, reason string) {
		ri, rj := find(i), find(j)
		if ri != rj {
			if ri < rj {
				parent[rj] = ri
			} else {
				parent[ri] = rj
			}
		}
		root := find(i)
		reasons[root] = append(reasons[root], reason)
	}

	for i := 0; i < len(active); i++ {
		for j := i + 1; j < len(active); j++ {
			if active[j].OccurredAt.Sub(active[i].OccurredAt) > c.window {
				break
			}
			if r := correlationReason(active[i], active[j]); r != "" {
				union(i, j, r)
			}
		}
	}

	groups := make(map[int][]contracts.Alert)
	groupReasons := make(map[int][]string)
	for i, a := range active {
		root := find(i)
		groups[root] = append(groups[root], a)
		groupReasons[root] = append(groupReasons[root], reasons[i]...)
	}

	roots := make([]int, 0, len(groups))
	for r := range groups {
		roots = append(roots, r)
	}
	sort.Ints(roots)

	cases := make([]contracts.Case, 0, len(roots))
	for _, root := range roots {
		grp := groups[root]
		cases = append(cases, buildCase(grp, groupReasons[root]))
	}

	sort.Slice(cases, func(i, j int) bool {
		if cases[i].FirstSeen.Equal(cases[j].FirstSeen) {
			return cases[i].CaseID < cases[j].CaseID
		}
		return cases[i].FirstSeen.Before(cases[j].FirstSeen)
	})
	return cases
}

func correlationReason(a, b contracts.Alert) string {
	// Keep telemetry health alerts separate from attacker/actor cases unless both are telemetry health
	if a.Category == "telemetry_health" || b.Category == "telemetry_health" {
		if a.Category == "telemetry_health" && b.Category == "telemetry_health" {
			return "shared_telemetry_pipeline_window"
		}
		return ""
	}
	if a.Actor != "" && a.Actor == b.Actor {
		return "shared_actor:" + a.Actor
	}
	if sa, sb := a.Evidence["session_id"], b.Evidence["session_id"]; sa != "" && sa == sb {
		return "shared_session:" + sa
	}
	if ta, tb := a.Evidence["change_ticket"], b.Evidence["change_ticket"]; ta != "" && ta == tb {
		return "shared_change_ticket:" + ta
	}
	if a.Host != "" && a.Host == b.Host && a.Service != "" && a.Service == b.Service {
		return fmt.Sprintf("shared_target:%s@%s", a.Service, a.Host)
	}
	return ""
}

func buildCase(alerts []contracts.Alert, rawReasons []string) contracts.Case {
	first := alerts[0].OccurredAt
	last := alerts[0].OccurredAt
	maxSev := alerts[0].Severity

	actorCounts := make(map[string]int)
	services := make([]string, 0, len(alerts))
	hosts := make([]string, 0, len(alerts))
	alertIDs := make([]string, 0, len(alerts))
	sourceEventIDs := make([]string, 0, len(alerts))
	timeline := make([]contracts.CaseTimelineEntry, 0, len(alerts))
	categories := make(map[string]bool)

	for _, a := range alerts {
		if a.OccurredAt.Before(first) {
			first = a.OccurredAt
		}
		if a.OccurredAt.After(last) {
			last = a.OccurredAt
		}
		maxSev = contracts.MaxSeverity(maxSev, a.Severity)
		actorCounts[a.Actor]++
		services = append(services, a.Service)
		hosts = append(hosts, a.Host)
		alertIDs = append(alertIDs, a.AlertID)
		sourceEventIDs = append(sourceEventIDs, a.SourceEventIDs...)
		categories[a.Category] = true
		timeline = append(timeline, contracts.CaseTimelineEntry{
			Timestamp:      a.OccurredAt,
			AlertID:        a.AlertID,
			RuleID:         a.RuleID,
			Severity:       a.Severity,
			Summary:        a.Summary,
			SourceEventIDs: contracts.SortedUnique(a.SourceEventIDs),
		})
	}

	primaryActor := pickPrimaryActor(actorCounts)
	sortedAlertIDs := contracts.SortedUnique(alertIDs)
	sortedEvents := contracts.SortedUnique(sourceEventIDs)
	sortedServices := contracts.SortedUnique(services)
	sortedHosts := contracts.SortedUnique(hosts)
	sortedReasons := contracts.SortedUnique(rawReasons)
	if len(sortedReasons) == 0 {
		sortedReasons = []string{"single_alert_case"}
	}

	caseID := contracts.StableID("CASE", primaryActor, strings.Join(sortedAlertIDs, ","))
	title := fmt.Sprintf("[%s] %d correlated alert(s) involving %s on %s",
		strings.ToUpper(string(maxSev)), len(alerts), primaryActor, strings.Join(sortedServices, ","))

	return contracts.Case{
		CaseID:             caseID,
		Title:              title,
		Severity:           maxSev,
		Status:             "open",
		FirstSeen:          first,
		LastSeen:           last,
		PrimaryActor:       primaryActor,
		AffectedServices:   sortedServices,
		AffectedHosts:      sortedHosts,
		AlertIDs:           sortedAlertIDs,
		SourceEventIDs:     sortedEvents,
		CorrelationReasons: sortedReasons,
		Timeline:           timeline,
		RecommendedActions: recommendSimulatedActions(categories),
	}
}

func pickPrimaryActor(counts map[string]int) string {
	best := ""
	bestCount := -1
	for actor, c := range counts {
		if c > bestCount || (c == bestCount && actor < best) {
			best = actor
			bestCount = c
		}
	}
	return best
}

func recommendSimulatedActions(categories map[string]bool) []string {
	actions := make([]string, 0)
	if categories["auth_log"] {
		actions = append(actions, "simulate_revoke_session")
	}
	if categories["config_diff"] {
		actions = append(actions, "simulate_revert_config_diff")
	}
	if categories["deployment_audit"] {
		actions = append(actions, "simulate_quarantine_host")
	}
	if categories["order_audit"] {
		actions = append(actions, "simulate_freeze_trading_credentials")
	}
	if categories["telemetry_health"] {
		actions = append(actions, "simulate_inspect_telemetry_collector")
	}
	sort.Strings(actions)
	return actions
}
