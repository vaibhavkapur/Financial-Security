package audit

import (
	"regexp"
	"strings"
)

const RedactedPlaceholder = "[REDACTED]"

var (
	jwtPattern       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	bearerPattern    = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`)
	pemKeyPattern    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	inlineKVSecretRe = regexp.MustCompile(`(?i)\b(secret|token|password|api[_-]?key|private[_-]?key|signature)\s*[:=]\s*([^\s,;"]+)`)
)

// Redactor removes secrets from headers, free text, and structured maps before logging.
type Redactor struct {
	sensitiveHeaders map[string]bool
	sensitiveKeys    map[string]bool
}

func NewRedactor(redactHeaders, redactJSONKeys []string) *Redactor {
	sh := make(map[string]bool, len(redactHeaders)+6)
	defaultsH := []string{"authorization", "x-signature", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
	for _, h := range defaultsH {
		sh[h] = true
	}
	for _, h := range redactHeaders {
		sh[strings.ToLower(strings.TrimSpace(h))] = true
	}

	sk := make(map[string]bool, len(redactJSONKeys)+9)
	defaultsK := []string{"secret", "token", "access_token", "refresh_token", "password", "private_key", "api_key", "client_secret", "signature"}
	for _, k := range defaultsK {
		sk[k] = true
	}
	for _, k := range redactJSONKeys {
		sk[strings.ToLower(strings.TrimSpace(k))] = true
	}

	return &Redactor{
		sensitiveHeaders: sh,
		sensitiveKeys:    sk,
	}
}

// RedactHeaders clones headers while replacing sensitive header values and inline secret tokens.
func (r *Redactor) RedactHeaders(headers map[string][]string) (map[string][]string, int) {
	out := make(map[string][]string, len(headers))
	count := 0
	for k, vals := range headers {
		lowerK := strings.ToLower(strings.TrimSpace(k))
		if r.sensitiveHeaders[lowerK] || strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "token") || strings.Contains(lowerK, "auth") {
			out[k] = []string{RedactedPlaceholder}
			count += len(vals)
			continue
		}
		cleanVals := make([]string, len(vals))
		for i, v := range vals {
			cv, n := r.RedactString(v)
			cleanVals[i] = cv
			count += n
		}
		out[k] = cleanVals
	}
	return out, count
}

// RedactString scrubs JWTs, Bearer strings, PEM private keys, and inline secret key-value pairs.
func (r *Redactor) RedactString(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	count := 0
	out := s

	if pemKeyPattern.MatchString(out) {
		out = pemKeyPattern.ReplaceAllString(out, RedactedPlaceholder)
		count++
	}
	if bearerPattern.MatchString(out) {
		out = bearerPattern.ReplaceAllString(out, "Bearer "+RedactedPlaceholder)
		count++
	}
	if jwtPattern.MatchString(out) {
		out = jwtPattern.ReplaceAllString(out, RedactedPlaceholder)
		count++
	}
	if inlineKVSecretRe.MatchString(out) {
		out = inlineKVSecretRe.ReplaceAllString(out, "$1="+RedactedPlaceholder)
		count++
	}
	return out, count
}

// RedactMap recursively scrubs sensitive keys and secret patterns in arbitrary JSON-like objects.
func (r *Redactor) RedactMap(m map[string]any) (map[string]any, int) {
	out := make(map[string]any, len(m))
	count := 0
	for k, v := range m {
		lowerK := strings.ToLower(strings.TrimSpace(k))
		if r.sensitiveKeys[lowerK] || strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "password") || strings.Contains(lowerK, "private_key") {
			out[k] = RedactedPlaceholder
			count++
			continue
		}
		switch typed := v.(type) {
		case string:
			cv, n := r.RedactString(typed)
			out[k] = cv
			count += n
		case map[string]any:
			cm, n := r.RedactMap(typed)
			out[k] = cm
			count += n
		default:
			out[k] = v
		}
	}
	return out, count
}
