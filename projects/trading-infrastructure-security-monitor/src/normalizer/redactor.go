package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"trading-infrastructure-security-monitor/src/contracts"
)

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

// Redactor scrubs sensitive fields and inline secret patterns deterministically.
type Redactor struct {
	policy         contracts.RedactionPolicy
	sensitiveNames map[string]struct{}
	patterns       []compiledPattern
}

func NewRedactor(policy contracts.RedactionPolicy) (*Redactor, error) {
	if policy.ReplacementToken == "" {
		policy.ReplacementToken = "[REDACTED]"
	}
	names := make(map[string]struct{}, len(policy.SensitiveFieldNames))
	for _, n := range policy.SensitiveFieldNames {
		names[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	patterns := make([]compiledPattern, 0, len(policy.ValuePatterns))
	for _, p := range policy.ValuePatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: redaction regex %q: %v", contracts.ErrInvalidConfig, p.Name, err)
		}
		patterns = append(patterns, compiledPattern{name: p.Name, re: re})
	}
	return &Redactor{
		policy:         policy,
		sensitiveNames: names,
		patterns:       patterns,
	}, nil
}

// RedactMap deep-copies and redacts a map, returning the sanitized map and deterministic audit records.
func (r *Redactor) RedactMap(prefix string, input map[string]any) (map[string]any, []contracts.RedactionRecord) {
	if len(input) == 0 {
		return map[string]any{}, []contracts.RedactionRecord{}
	}
	records := make([]contracts.RedactionRecord, 0)
	out := r.redactMapRecursive(prefix, input, &records)
	sort.Slice(records, func(i, j int) bool {
		if records[i].FieldPath == records[j].FieldPath {
			return records[i].Reason < records[j].Reason
		}
		return records[i].FieldPath < records[j].FieldPath
	})
	return out, records
}

func (r *Redactor) redactMapRecursive(prefix string, input map[string]any, records *[]contracts.RedactionRecord) map[string]any {
	out := make(map[string]any, len(input))
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := input[k]
		fieldPath := k
		if prefix != "" {
			fieldPath = prefix + "." + k
		}
		if r.isSensitiveFieldName(k) {
			rawStr := fmt.Sprint(val)
			*records = append(*records, contracts.RedactionRecord{
				FieldPath:         fieldPath,
				Reason:            "sensitive_field_name",
				ValueSHA256Prefix: r.fingerprint(rawStr),
			})
			out[k] = r.policy.ReplacementToken
			continue
		}
		out[k] = r.redactValue(fieldPath, val, records)
	}
	return out
}

func (r *Redactor) redactValue(fieldPath string, val any, records *[]contracts.RedactionRecord) any {
	switch typed := val.(type) {
	case map[string]any:
		return r.redactMapRecursive(fieldPath, typed, records)
	case []any:
		res := make([]any, len(typed))
		for i, item := range typed {
			res[i] = r.redactValue(fmt.Sprintf("%s[%d]", fieldPath, i), item, records)
		}
		return res
	case string:
		redacted, matchedPattern := r.RedactString(typed)
		if matchedPattern != "" {
			*records = append(*records, contracts.RedactionRecord{
				FieldPath:         fieldPath,
				Reason:            "pattern:" + matchedPattern,
				ValueSHA256Prefix: r.fingerprint(typed),
			})
		}
		return redacted
	default:
		return val
	}
}

// RedactString applies all configured value regexes to a string.
func (r *Redactor) RedactString(s string) (string, string) {
	result := s
	matched := ""
	for _, p := range r.patterns {
		if p.re.MatchString(result) {
			if matched == "" {
				matched = p.name
			}
			result = p.re.ReplaceAllString(result, r.policy.ReplacementToken)
		}
	}
	return result, matched
}

func (r *Redactor) isSensitiveFieldName(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if _, ok := r.sensitiveNames[lower]; ok {
		return true
	}
	for name := range r.sensitiveNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

func (r *Redactor) fingerprint(raw string) string {
	if !r.policy.PreserveSHA256Fingerprint || raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}
