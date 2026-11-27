package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

var supportedHTTPMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

// IsSupportedMethod reports whether an HTTP method is permitted by the gateway.
func IsSupportedMethod(method string) bool {
	return supportedHTTPMethods[strings.ToUpper(strings.TrimSpace(method))]
}

// LoadGatewayConfig reads and strictly validates a gateway configuration JSON file.
func LoadGatewayConfig(path string) (GatewayConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return GatewayConfig{}, fmt.Errorf("read gateway config %q: %w", path, err)
	}
	var cfg GatewayConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return GatewayConfig{}, fmt.Errorf("parse gateway config %q: %w", path, err)
	}
	if err := ValidateGatewayConfig(cfg); err != nil {
		return GatewayConfig{}, fmt.Errorf("invalid gateway config %q: %w", path, err)
	}
	return cfg, nil
}

// ValidateGatewayConfig enforces required settings and fail-closed security invariants.
func ValidateGatewayConfig(cfg GatewayConfig) error {
	var errs []string
	if strings.TrimSpace(cfg.SchemaVersion) == "" {
		errs = append(errs, "schema_version is required")
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		errs = append(errs, "listen_addr is required")
	}
	if strings.TrimSpace(cfg.UpstreamURL) == "" {
		errs = append(errs, "upstream_url is required")
	} else if u, err := url.Parse(cfg.UpstreamURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, "upstream_url must be a valid http or https URL")
	}
	if cfg.UpstreamTimeoutMs <= 0 {
		errs = append(errs, "upstream_timeout_ms must be > 0")
	}
	if !cfg.DenyByDefault {
		errs = append(errs, "deny_by_default must be true (fail-closed policy invariant)")
	}
	if strings.TrimSpace(cfg.OIDC.Issuer) == "" {
		errs = append(errs, "oidc.issuer is required")
	}
	if strings.TrimSpace(cfg.OIDC.Audience) == "" {
		errs = append(errs, "oidc.audience is required")
	}
	if len(cfg.OIDC.AllowedAlgorithms) == 0 {
		errs = append(errs, "oidc.allowed_algorithms must not be empty")
	}
	for _, alg := range cfg.OIDC.AllowedAlgorithms {
		if alg != "EdDSA" && alg != "ES256" {
			errs = append(errs, fmt.Sprintf("unsupported oidc algorithm %q (allowed: EdDSA, ES256)", alg))
		}
	}
	if cfg.OIDC.MaxClockSkewSeconds < 0 {
		errs = append(errs, "oidc.max_clock_skew_seconds must be >= 0")
	}
	if cfg.Signing.MaxRequestAgeSeconds <= 0 {
		errs = append(errs, "signing.max_request_age_seconds must be > 0")
	}
	if cfg.Signing.MaxFutureSkewSeconds < 0 {
		errs = append(errs, "signing.max_future_skew_seconds must be >= 0")
	}
	if cfg.Signing.NonceTTLSeconds <= 0 {
		errs = append(errs, "signing.nonce_ttl_seconds must be > 0")
	}
	if cfg.Signing.MaxNonceEntries <= 0 {
		errs = append(errs, "signing.max_nonce_entries must be > 0")
	}
	if cfg.RateLimit.DefaultRequestsPerSecond <= 0 || cfg.RateLimit.DefaultBurst <= 0 {
		errs = append(errs, "rate_limit default_requests_per_second and default_burst must be > 0")
	}
	if cfg.Audit.MaxBodyBytes <= 0 {
		errs = append(errs, "audit.max_body_bytes must be > 0")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// LoadPolicySet reads and strictly validates authorization policies.
func LoadPolicySet(path string) (PolicySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PolicySet{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	var ps PolicySet
	if err := json.Unmarshal(raw, &ps); err != nil {
		return PolicySet{}, fmt.Errorf("parse policy file %q: %w", path, err)
	}
	if err := ValidatePolicySet(ps); err != nil {
		return PolicySet{}, fmt.Errorf("invalid policy file %q: %w", path, err)
	}
	return ps, nil
}

// ValidatePolicySet checks that policies are versioned, deny-by-default, and well-formed.
func ValidatePolicySet(ps PolicySet) error {
	var errs []string
	if strings.TrimSpace(ps.SchemaVersion) == "" {
		errs = append(errs, "schema_version is required")
	}
	if strings.TrimSpace(ps.PolicyVersion) == "" {
		errs = append(errs, "policy_version is required")
	}
	if strings.ToLower(strings.TrimSpace(ps.DefaultEffect)) != "deny" {
		errs = append(errs, "default_effect must be \"deny\"")
	}
	seenIDs := make(map[string]bool)
	for i, r := range ps.Rules {
		if strings.TrimSpace(r.ID) == "" {
			errs = append(errs, fmt.Sprintf("rules[%d].id is required", i))
		} else if seenIDs[r.ID] {
			errs = append(errs, fmt.Sprintf("duplicate policy rule id %q", r.ID))
		} else {
			seenIDs[r.ID] = true
		}
		if !IsSupportedMethod(r.Method) {
			errs = append(errs, fmt.Sprintf("rules[%d].method %q is unsupported", i, r.Method))
		}
		if !strings.HasPrefix(r.PathPattern, "/") {
			errs = append(errs, fmt.Sprintf("rules[%d].path_pattern %q must start with '/'", i, r.PathPattern))
		}
		if len(r.RequiredScopes) == 0 {
			errs = append(errs, fmt.Sprintf("rules[%d].required_scopes must not be empty", i))
		}
		if len(r.AllowedRoles) == 0 {
			errs = append(errs, fmt.Sprintf("rules[%d].allowed_roles must not be empty", i))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// LoadClientRegistry reads and strictly validates mock client identities.
func LoadClientRegistry(path string) (ClientRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ClientRegistry{}, fmt.Errorf("read client registry %q: %w", path, err)
	}
	var reg ClientRegistry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return ClientRegistry{}, fmt.Errorf("parse client registry %q: %w", path, err)
	}
	if err := ValidateClientRegistry(reg); err != nil {
		return ClientRegistry{}, fmt.Errorf("invalid client registry %q: %w", path, err)
	}
	return reg, nil
}

// ValidateClientRegistry verifies unique client IDs and valid statuses.
func ValidateClientRegistry(reg ClientRegistry) error {
	var errs []string
	if strings.TrimSpace(reg.SchemaVersion) == "" {
		errs = append(errs, "schema_version is required")
	}
	seen := make(map[string]bool)
	for i, c := range reg.Clients {
		if strings.TrimSpace(c.ClientID) == "" {
			errs = append(errs, fmt.Sprintf("clients[%d].client_id is required", i))
		} else if seen[c.ClientID] {
			errs = append(errs, fmt.Sprintf("duplicate client_id %q", c.ClientID))
		} else {
			seen[c.ClientID] = true
		}
		if strings.TrimSpace(c.Role) == "" {
			errs = append(errs, fmt.Sprintf("clients[%d].role is required", i))
		}
		if c.Status != "active" && c.Status != "revoked" {
			errs = append(errs, fmt.Sprintf("clients[%d].status %q must be active or revoked", i, c.Status))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
