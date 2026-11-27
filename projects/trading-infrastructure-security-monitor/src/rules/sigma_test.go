package rules

import (
	"errors"
	"testing"

	"trading-infrastructure-security-monitor/src/contracts"
)

func TestParseAndMatchSigmaRule(t *testing.T) {
	yamlDoc := `
title: Test Protected Config Edit
id: TEST-001
status: stable
level: high
logsource:
  category: config_diff
detection:
  selection_path:
    event_type: config_diff
    attributes.config_path|startswith: /etc/trading/
  selection_action:
    action|in:
      - config_edit
      - direct_write
  filter_ci:
    actor: svc-ci-deployer
    attributes.change_ticket_valid: "true"
  condition: (selection_path and selection_action) and not filter_ci
tags:
  - trading.config
`
	r, err := ParseSigmaYAML(yamlDoc)
	if err != nil {
		t.Fatalf("ParseSigmaYAML failed: %v", err)
	}

	unauth := contracts.NormalizedEvent{
		EventID:   "e1",
		EventType: contracts.EventTypeConfigDiff,
		Actor:     "rogue-dev",
		Action:    "config_edit",
		Attributes: map[string]string{
			"config_path":         "/etc/trading/risk-engine/limits.yaml",
			"change_ticket_valid": "false",
		},
	}
	if !r.Match(unauth) {
		t.Fatalf("expected unauthorized config edit to match rule")
	}

	authCI := contracts.NormalizedEvent{
		EventID:   "e2",
		EventType: contracts.EventTypeConfigDiff,
		Actor:     "svc-ci-deployer",
		Action:    "config_edit",
		Attributes: map[string]string{
			"config_path":         "/etc/trading/order-router/routing.yaml",
			"change_ticket_valid": "true",
		},
	}
	if r.Match(authCI) {
		t.Fatalf("expected authorized CI config edit to be filtered out")
	}
}

func TestParseSigmaRuleRejectsBrokenCondition(t *testing.T) {
	bad := `
title: Broken Rule
id: BAD-001
level: low
detection:
  selection_a:
    action: login
  condition: selection_a and selection_missing
`
	_, err := ParseSigmaYAML(bad)
	if !errors.Is(err, contracts.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for undefined selection, got %v", err)
	}
}

func TestSigmaQuantifierAndRegexModifiers(t *testing.T) {
	yamlDoc := `
title: Quantifier And Regex
id: TEST-002
level: medium
detection:
  selection_a:
    attributes.config_path|re: ^/etc/trading/(risk|order)-.*/.*\.yaml$
  selection_b:
    action|endswith: _override
  condition: 1 of selection*
`
	r, err := ParseSigmaYAML(yamlDoc)
	if err != nil {
		t.Fatalf("ParseSigmaYAML failed: %v", err)
	}
	ev := contracts.NormalizedEvent{
		EventType: contracts.EventTypeConfigDiff,
		Action:    "edit",
		Attributes: map[string]string{
			"config_path": "/etc/trading/risk-engine/limits.yaml",
		},
	}
	if !r.Match(ev) {
		t.Fatalf("expected regex selection_a to satisfy 1 of selection*")
	}
}
