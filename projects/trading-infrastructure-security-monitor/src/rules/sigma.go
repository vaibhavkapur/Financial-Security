package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"trading-infrastructure-security-monitor/src/contracts"
)

// SigmaRule represents a parsed Sigma-style detection rule.
type SigmaRule struct {
	ID          string
	Title       string
	Status      string
	Level       contracts.Severity
	Description string
	LogSource   map[string]string
	Selections  map[string][]FieldMatcher
	Condition   string
	Tags        []string
	condAST     condNode
}

// FieldMatcher matches a single field with an optional modifier (|contains, |startswith, |endswith, |in, |re, |neq).
type FieldMatcher struct {
	Field    string
	Modifier string
	Values   []string
	regexes  []*regexp.Regexp
}

// LoadRulesDir reads and validates all .yaml/.yml Sigma rule files from dir in deterministic sorted order.
func LoadRulesDir(dir string) ([]SigmaRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: rules directory %s", contracts.ErrMissingConfig, dir)
		}
		return nil, fmt.Errorf("read rules dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: no Sigma rule files found in %s", contracts.ErrMissingConfig, dir)
	}

	rules := make([]SigmaRule, 0, len(names))
	seenIDs := make(map[string]bool)
	for _, name := range names {
		full := filepath.Join(dir, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", full, err)
		}
		r, err := ParseSigmaYAML(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", name, err)
		}
		if seenIDs[r.ID] {
			return nil, fmt.Errorf("%w: duplicate rule id %q", contracts.ErrInvalidConfig, r.ID)
		}
		seenIDs[r.ID] = true
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

// ParseSigmaYAML parses a subset of YAML used by Sigma detection rules.
func ParseSigmaYAML(content string) (SigmaRule, error) {
	rule := SigmaRule{
		LogSource:  make(map[string]string),
		Selections: make(map[string][]FieldMatcher),
		Tags:       []string{},
	}

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	section := ""
	currentSelection := ""
	var currentMatcher *FieldMatcher

	flushMatcher := func() error {
		if currentMatcher == nil || currentSelection == "" {
			return nil
		}
		if currentMatcher.Modifier == "re" {
			for _, v := range currentMatcher.Values {
				re, err := regexp.Compile(v)
				if err != nil {
					return fmt.Errorf("%w: invalid regex %q in field %s: %v", contracts.ErrInvalidConfig, v, currentMatcher.Field, err)
				}
				currentMatcher.regexes = append(currentMatcher.regexes, re)
			}
		}
		rule.Selections[currentSelection] = append(rule.Selections[currentSelection], *currentMatcher)
		currentMatcher = nil
		return nil
	}

	for lineIdx, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := countLeadingSpaces(rawLine)

		if indent == 0 {
			if err := flushMatcher(); err != nil {
				return SigmaRule{}, err
			}
			currentSelection = ""
			k, v, ok := splitYAMLKV(trimmed)
			if !ok {
				return SigmaRule{}, fmt.Errorf("%w: line %d invalid top-level syntax %q", contracts.ErrInvalidConfig, lineIdx+1, trimmed)
			}
			section = k
			switch k {
			case "title":
				rule.Title = unquote(v)
			case "id":
				rule.ID = unquote(v)
			case "status":
				rule.Status = unquote(v)
			case "level":
				rule.Level = contracts.Severity(strings.ToLower(unquote(v)))
			case "description":
				rule.Description = unquote(v)
			case "logsource", "detection", "tags":
				// nested blocks
			default:
				// ignore unknown metadata keys
			}
			continue
		}

		switch section {
		case "logsource":
			k, v, ok := splitYAMLKV(trimmed)
			if !ok {
				return SigmaRule{}, fmt.Errorf("%w: line %d invalid logsource entry", contracts.ErrInvalidConfig, lineIdx+1)
			}
			rule.LogSource[k] = unquote(v)
		case "tags":
			if strings.HasPrefix(trimmed, "- ") {
				rule.Tags = append(rule.Tags, unquote(strings.TrimSpace(trimmed[2:])))
			}
		case "detection":
			if indent == 2 {
				if err := flushMatcher(); err != nil {
					return SigmaRule{}, err
				}
				k, v, ok := splitYAMLKV(trimmed)
				if !ok {
					return SigmaRule{}, fmt.Errorf("%w: line %d invalid detection entry", contracts.ErrInvalidConfig, lineIdx+1)
				}
				if k == "condition" {
					rule.Condition = unquote(v)
					currentSelection = ""
				} else {
					currentSelection = k
					if _, exists := rule.Selections[currentSelection]; !exists {
						rule.Selections[currentSelection] = []FieldMatcher{}
					}
				}
			} else if indent == 4 && currentSelection != "" {
				if err := flushMatcher(); err != nil {
					return SigmaRule{}, err
				}
				k, v, ok := splitYAMLKV(trimmed)
				if !ok {
					return SigmaRule{}, fmt.Errorf("%w: line %d invalid matcher entry", contracts.ErrInvalidConfig, lineIdx+1)
				}
				field, mod := splitFieldModifier(k)
				fm := FieldMatcher{Field: field, Modifier: mod}
				if v != "" {
					fm.Values = []string{unquote(v)}
				}
				currentMatcher = &fm
			} else if indent >= 6 && currentMatcher != nil {
				if !strings.HasPrefix(trimmed, "- ") {
					return SigmaRule{}, fmt.Errorf("%w: line %d expected list item", contracts.ErrInvalidConfig, lineIdx+1)
				}
				currentMatcher.Values = append(currentMatcher.Values, unquote(strings.TrimSpace(trimmed[2:])))
			}
		}
	}
	if err := flushMatcher(); err != nil {
		return SigmaRule{}, err
	}

	if err := rule.validate(); err != nil {
		return SigmaRule{}, err
	}
	ast, err := parseCondition(rule.Condition, rule.Selections)
	if err != nil {
		return SigmaRule{}, err
	}
	rule.condAST = ast
	return rule, nil
}

func (r *SigmaRule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("%w: rule id is required", contracts.ErrInvalidConfig)
	}
	if r.Title == "" {
		return fmt.Errorf("%w: rule %s title is required", contracts.ErrInvalidConfig, r.ID)
	}
	if !r.Level.IsValid() {
		return fmt.Errorf("%w: rule %s invalid level %q", contracts.ErrInvalidConfig, r.ID, r.Level)
	}
	if strings.TrimSpace(r.Condition) == "" {
		return fmt.Errorf("%w: rule %s detection.condition is required", contracts.ErrInvalidConfig, r.ID)
	}
	for selName, matchers := range r.Selections {
		for _, m := range matchers {
			switch m.Modifier {
			case "", "contains", "startswith", "endswith", "in", "re", "neq":
			default:
				return fmt.Errorf("%w: rule %s selection %s unsupported modifier %q", contracts.ErrInvalidConfig, r.ID, selName, m.Modifier)
			}
			if len(m.Values) == 0 {
				return fmt.Errorf("%w: rule %s selection %s field %s has no values", contracts.ErrInvalidConfig, r.ID, selName, m.Field)
			}
		}
	}
	return nil
}

// Match evaluates the Sigma rule against a NormalizedEvent.
func (r *SigmaRule) Match(ev contracts.NormalizedEvent) bool {
	if cat, ok := r.LogSource["category"]; ok && cat != "" && string(ev.EventType) != cat {
		return false
	}
	selResults := make(map[string]bool, len(r.Selections))
	for selName, matchers := range r.Selections {
		selResults[selName] = matchAllFields(ev, matchers)
	}
	return r.condAST.eval(selResults)
}

func matchAllFields(ev contracts.NormalizedEvent, matchers []FieldMatcher) bool {
	if len(matchers) == 0 {
		return false
	}
	for _, m := range matchers {
		actual, ok := lookupEventField(ev, m.Field)
		if !matchFieldValue(actual, ok, m) {
			return false
		}
	}
	return true
}

func lookupEventField(ev contracts.NormalizedEvent, field string) (string, bool) {
	if strings.HasPrefix(field, "attributes.") {
		key := strings.TrimPrefix(field, "attributes.")
		v, ok := ev.Attributes[key]
		return v, ok
	}
	switch field {
	case "event_id":
		return ev.EventID, true
	case "event_type":
		return string(ev.EventType), true
	case "actor":
		return ev.Actor, true
	case "service":
		return ev.Service, true
	case "host":
		return ev.Host, true
	case "action":
		return ev.Action, true
	case "outcome":
		return ev.Outcome, true
	case "source_ip":
		return ev.SourceIP, ev.SourceIP != ""
	case "change_ticket":
		return ev.ChangeTicket, ev.ChangeTicket != ""
	case "session_id":
		return ev.SessionID, ev.SessionID != ""
	default:
		v, ok := ev.Attributes[field]
		return v, ok
	}
}

func matchFieldValue(actual string, exists bool, m FieldMatcher) bool {
	if !exists && m.Modifier != "neq" {
		return false
	}
	actualLower := strings.ToLower(actual)
	switch m.Modifier {
	case "", "in":
		for _, want := range m.Values {
			if actualLower == strings.ToLower(want) {
				return true
			}
		}
		return false
	case "neq":
		if !exists {
			return true
		}
		for _, want := range m.Values {
			if actualLower == strings.ToLower(want) {
				return false
			}
		}
		return true
	case "contains":
		for _, want := range m.Values {
			if strings.Contains(actualLower, strings.ToLower(want)) {
				return true
			}
		}
		return false
	case "startswith":
		for _, want := range m.Values {
			if strings.HasPrefix(actualLower, strings.ToLower(want)) {
				return true
			}
		}
		return false
	case "endswith":
		for _, want := range m.Values {
			if strings.HasSuffix(actualLower, strings.ToLower(want)) {
				return true
			}
		}
		return false
	case "re":
		for _, re := range m.regexes {
			if re.MatchString(actual) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// --- Boolean condition AST parser ---

type condNode interface {
	eval(sel map[string]bool) bool
}

type identNode struct{ name string }

func (n identNode) eval(sel map[string]bool) bool { return sel[n.name] }

type notNode struct{ child condNode }

func (n notNode) eval(sel map[string]bool) bool { return !n.child.eval(sel) }

type andNode struct{ left, right condNode }

func (n andNode) eval(sel map[string]bool) bool { return n.left.eval(sel) && n.right.eval(sel) }

type orNode struct{ left, right condNode }

func (n orNode) eval(sel map[string]bool) bool { return n.left.eval(sel) || n.right.eval(sel) }

type quantNode struct {
	requireAll bool
	names      []string
}

func (n quantNode) eval(sel map[string]bool) bool {
	if len(n.names) == 0 {
		return false
	}
	if n.requireAll {
		for _, name := range n.names {
			if !sel[name] {
				return false
			}
		}
		return true
	}
	for _, name := range n.names {
		if sel[name] {
			return true
		}
	}
	return false
}

type condParser struct {
	tokens     []string
	pos        int
	selections map[string][]FieldMatcher
}

func tokenizeCondition(expr string) []string {
	spaced := strings.ReplaceAll(expr, "(", " ( ")
	spaced = strings.ReplaceAll(spaced, ")", " ) ")
	return strings.Fields(spaced)
}

func parseCondition(expr string, selections map[string][]FieldMatcher) (condNode, error) {
	p := &condParser{
		tokens:     tokenizeCondition(expr),
		selections: selections,
	}
	if len(p.tokens) == 0 {
		return nil, fmt.Errorf("%w: empty condition", contracts.ErrInvalidConfig)
	}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected token %q in condition %q", contracts.ErrInvalidConfig, p.tokens[p.pos], expr)
	}
	return node, nil
}

func (p *condParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *condParser) parseOr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.pos++
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.pos++
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{child: child}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condNode, error) {
	tok := p.peek()
	if tok == "" {
		return nil, fmt.Errorf("%w: unexpected end of condition", contracts.ErrInvalidConfig)
	}
	if tok == "(" {
		p.pos++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("%w: missing closing parenthesis in condition", contracts.ErrInvalidConfig)
		}
		p.pos++
		return node, nil
	}
	// Support "1 of selection*" and "all of selection*"
	if (tok == "1" || strings.EqualFold(tok, "all")) && p.pos+2 < len(p.tokens) && strings.EqualFold(p.tokens[p.pos+1], "of") {
		reqAll := strings.EqualFold(tok, "all")
		pattern := p.tokens[p.pos+2]
		p.pos += 3
		matched := matchSelectionPattern(pattern, p.selections)
		if len(matched) == 0 {
			return nil, fmt.Errorf("%w: quantifier pattern %q matches no selections", contracts.ErrInvalidConfig, pattern)
		}
		return quantNode{requireAll: reqAll, names: matched}, nil
	}
	p.pos++
	if _, ok := p.selections[tok]; !ok {
		return nil, fmt.Errorf("%w: condition references undefined selection %q", contracts.ErrInvalidConfig, tok)
	}
	return identNode{name: tok}, nil
}

func matchSelectionPattern(pattern string, selections map[string][]FieldMatcher) []string {
	out := make([]string, 0)
	if pattern == "them" {
		for k := range selections {
			out = append(out, k)
		}
	} else if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		for k := range selections {
			if strings.HasPrefix(k, prefix) {
				out = append(out, k)
			}
		}
	} else if _, ok := selections[pattern]; ok {
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

func countLeadingSpaces(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}

func splitYAMLKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func splitFieldModifier(k string) (string, string) {
	idx := strings.IndexByte(k, '|')
	if idx < 0 {
		return k, ""
	}
	return k[:idx], strings.ToLower(k[idx+1:])
}

func unquote(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		return v[1 : len(v)-1]
	}
	return v
}
