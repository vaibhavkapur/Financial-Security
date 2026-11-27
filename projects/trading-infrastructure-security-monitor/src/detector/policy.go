package detector

import (
	"fmt"
	"net"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

// PolicyEvaluator enforces deny-by-default authorization and identity/policy enrichment.
type PolicyEvaluator struct {
	policy        contracts.SecurityPolicy
	trustedNets   []*net.IPNet
	deployActors  map[string]bool
	configEditors map[string]bool
	privRoles     map[string]bool
	svcAccounts   map[string]bool
	tickets       map[string]parsedTicket
}

type parsedTicket struct {
	raw          contracts.ApprovedChangeTicket
	windowStart  time.Time
	windowEnd    time.Time
	allowedPaths map[string]bool
}

func NewPolicyEvaluator(policy contracts.SecurityPolicy) (*PolicyEvaluator, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	pe := &PolicyEvaluator{
		policy:        policy,
		deployActors:  toLowerSet(policy.AllowedDeploymentActors),
		configEditors: toLowerSet(policy.AllowedConfigEditors),
		privRoles:     toLowerSet(policy.PrivilegedRoles),
		svcAccounts:   toLowerSet(policy.ServiceAccounts),
		tickets:       make(map[string]parsedTicket, len(policy.ApprovedChangeTickets)),
	}
	for _, cidr := range policy.TrustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%w: CIDR %q: %v", contracts.ErrInvalidConfig, cidr, err)
		}
		pe.trustedNets = append(pe.trustedNets, ipNet)
	}
	for _, t := range policy.ApprovedChangeTickets {
		ws, err := time.Parse(time.RFC3339, t.WindowStart)
		if err != nil {
			return nil, fmt.Errorf("%w: ticket %s window_start: %v", contracts.ErrInvalidConfig, t.TicketID, err)
		}
		we, err := time.Parse(time.RFC3339, t.WindowEnd)
		if err != nil {
			return nil, fmt.Errorf("%w: ticket %s window_end: %v", contracts.ErrInvalidConfig, t.TicketID, err)
		}
		paths := make(map[string]bool, len(t.AllowedPaths))
		for _, p := range t.AllowedPaths {
			paths[strings.TrimSpace(p)] = true
		}
		pe.tickets[strings.ToUpper(strings.TrimSpace(t.TicketID))] = parsedTicket{
			raw:          t,
			windowStart:  ws.UTC(),
			windowEnd:    we.UTC(),
			allowedPaths: paths,
		}
	}
	return pe, nil
}

// EnrichEvent returns a copy of ev annotated with deny-by-default policy evaluation attributes.
func (pe *PolicyEvaluator) EnrichEvent(ev contracts.NormalizedEvent) contracts.NormalizedEvent {
	enriched := ev
	attrs := make(map[string]string, len(ev.Attributes)+8)
	for k, v := range ev.Attributes {
		attrs[k] = v
	}

	attrs["is_service_account"] = boolStr(pe.svcAccounts[ev.Actor])
	attrs["source_ip_trusted"] = boolStr(pe.isTrustedIP(ev.SourceIP))
	attrs["off_hours"] = boolStr(pe.isOffHours(ev.OccurredAt))

	if role, ok := attrs["target_role"]; ok {
		attrs["is_privileged_role"] = boolStr(pe.privRoles[strings.ToLower(role)])
	}
	if cfgPath, ok := attrs["config_path"]; ok {
		attrs["is_protected_config_path"] = boolStr(pe.isProtectedConfigPath(cfgPath))
	}

	ticketValid, deployAuthorized, reason := pe.evaluateChangeAuthorization(ev, attrs)
	attrs["change_ticket_valid"] = boolStr(ticketValid)
	attrs["deployment_authorized"] = boolStr(deployAuthorized)
	attrs["policy_decision_reason"] = reason

	enriched.Attributes = attrs
	return enriched
}

func (pe *PolicyEvaluator) evaluateChangeAuthorization(ev contracts.NormalizedEvent, attrs map[string]string) (ticketValid bool, deployAuthorized bool, reason string) {
	// Deny by default
	if ev.ChangeTicket == "" {
		return false, false, "deny: missing change_ticket"
	}
	pt, exists := pe.tickets[strings.ToUpper(ev.ChangeTicket)]
	if !exists {
		return false, false, fmt.Sprintf("deny: unknown change_ticket %s", ev.ChangeTicket)
	}
	if strings.ToLower(pt.raw.Actor) != ev.Actor {
		return false, false, fmt.Sprintf("deny: ticket %s actor mismatch (expected %s, got %s)", ev.ChangeTicket, pt.raw.Actor, ev.Actor)
	}
	if strings.ToLower(pt.raw.Service) != ev.Service {
		return false, false, fmt.Sprintf("deny: ticket %s service mismatch (expected %s, got %s)", ev.ChangeTicket, pt.raw.Service, ev.Service)
	}
	if ev.OccurredAt.Before(pt.windowStart) || ev.OccurredAt.After(pt.windowEnd) {
		return false, false, fmt.Sprintf("deny: event time %s outside ticket %s approved window", ev.OccurredAt.Format(time.RFC3339), ev.ChangeTicket)
	}

	switch ev.EventType {
	case contracts.EventTypeConfigDiff:
		if !pe.configEditors[ev.Actor] {
			return false, false, fmt.Sprintf("deny: actor %s is not in allowed_config_editors", ev.Actor)
		}
		cfgPath := strings.TrimSpace(attrs["config_path"])
		if !pt.allowedPaths[cfgPath] {
			return false, false, fmt.Sprintf("deny: config_path %s not approved in ticket %s", cfgPath, ev.ChangeTicket)
		}
		return true, false, fmt.Sprintf("allow: approved config_diff under ticket %s", ev.ChangeTicket)

	case contracts.EventTypeDeploymentAudit:
		if !pe.deployActors[ev.Actor] {
			return false, false, fmt.Sprintf("deny: actor %s is not in allowed_deployment_actors", ev.Actor)
		}
		gotSHA := strings.ToLower(strings.TrimSpace(attrs["artifact_sha256"]))
		wantSHA := strings.ToLower(strings.TrimSpace(pt.raw.ExpectedArtifactSHA256))
		if wantSHA == "" || gotSHA != wantSHA {
			return false, false, fmt.Sprintf("deny: artifact_sha256 mismatch for ticket %s", ev.ChangeTicket)
		}
		return true, true, fmt.Sprintf("allow: verified deployment under ticket %s", ev.ChangeTicket)

	default:
		return true, false, fmt.Sprintf("allow: approved ticket %s within window", ev.ChangeTicket)
	}
}

func (pe *PolicyEvaluator) isTrustedIP(ipStr string) bool {
	if ipStr == "" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range pe.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (pe *PolicyEvaluator) isOffHours(t time.Time) bool {
	hour := t.UTC().Hour()
	return hour < pe.policy.AllowedBusinessHoursUTC.StartHour || hour >= pe.policy.AllowedBusinessHoursUTC.EndHour
}

func (pe *PolicyEvaluator) isProtectedConfigPath(path string) bool {
	for _, prefix := range pe.policy.ProtectedConfigPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func toLowerSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[strings.ToLower(strings.TrimSpace(it))] = true
	}
	return m
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
