package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// StorageConfig configures the persistence adapter.
type StorageConfig struct {
	Driver string `json:"driver"` // "sqlite" (default) or "postgres"
	DSN    string `json:"dsn"`
}

// RedactionConfig controls sensitive field scrubbing in telemetry and audit logs.
type RedactionConfig struct {
	RedactFields []string `json:"redact_fields"`
	Replacement  string   `json:"replacement"`
}

// EvaluationConfig controls deterministic adversarial/benchmark evaluation.
type EvaluationConfig struct {
	RandomSeed int64 `json:"random_seed"`
}

// Config is the pinned runtime configuration for AIAP.
type Config struct {
	SchemaVersion          string           `json:"schema_version"`
	PolicyVersion          string           `json:"policy_version"`
	IssuerID               string           `json:"issuer_id"`
	SigningAlgorithm       string           `json:"signing_algorithm"`
	DefaultGrantTTLSeconds int64            `json:"default_grant_ttl_seconds"`
	MaxGrantTTLSeconds     int64            `json:"max_grant_ttl_seconds"`
	MaxApprovalTTLSeconds  int64            `json:"max_approval_ttl_seconds"`
	MaxDelegationDepth     int              `json:"max_delegation_depth"`
	ClockSkewSeconds       int64            `json:"clock_skew_seconds"`
	DenyByDefault          bool             `json:"deny_by_default"`
	AllowedAudiences       []string         `json:"allowed_audiences"`
	SupportedActionTypes   []string         `json:"supported_action_types"`
	SupportedCurrencies    []string         `json:"supported_currencies"`
	Storage                StorageConfig    `json:"storage"`
	Redaction              RedactionConfig  `json:"redaction"`
	Evaluation             EvaluationConfig `json:"evaluation"`
}

// ErrInvalidConfig signals a configuration failure.
var ErrInvalidConfig = errors.New("ERR_INVALID_CONFIG")

// DefaultConfig returns a valid deterministic baseline configuration.
func DefaultConfig() Config {
	return Config{
		SchemaVersion:          "1.0.0",
		PolicyVersion:          "aiap-policy-v1.0.0",
		IssuerID:               "aiap-authority.mock.local",
		SigningAlgorithm:       "EdDSA",
		DefaultGrantTTLSeconds: 300,
		MaxGrantTTLSeconds:     900,
		MaxApprovalTTLSeconds:  300,
		MaxDelegationDepth:     2,
		ClockSkewSeconds:       0,
		DenyByDefault:          true,
		AllowedAudiences: []string{
			"mock-treasury-api",
			"mock-settlement-engine",
			"mock-portfolio-rebalancer",
			"mock-market-data-readonly",
		},
		SupportedActionTypes: []string{
			"payment.initiate",
			"trade.execute",
			"portfolio.rebalance",
			"account.read",
		},
		SupportedCurrencies: []string{"USD", "EUR", "GBP"},
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "file::memory:?cache=shared",
		},
		Redaction: RedactionConfig{
			RedactFields: []string{
				"bearer_token",
				"raw_jwt",
				"private_key",
				"secret",
				"api_key",
				"password",
				"ssn",
				"tax_id",
				"memo_pii",
			},
			Replacement: "[REDACTED]",
		},
		Evaluation: EvaluationConfig{
			RandomSeed: 20261127,
		},
	}
}

// LoadFromFile reads and strictly validates a JSON configuration file.
func LoadFromFile(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("%w: config file path is empty", ErrInvalidConfig)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("%w: failed to read config file %q: %v", ErrInvalidConfig, path, err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: invalid JSON in %q: %v", ErrInvalidConfig, path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces fail-closed invariants on all configuration fields.
func (c Config) Validate() error {
	if strings.TrimSpace(c.SchemaVersion) == "" {
		return fmt.Errorf("%w: schema_version is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.PolicyVersion) == "" {
		return fmt.Errorf("%w: policy_version is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.IssuerID) == "" {
		return fmt.Errorf("%w: issuer_id is required", ErrInvalidConfig)
	}
	if c.SigningAlgorithm != "EdDSA" {
		return fmt.Errorf("%w: unsupported signing_algorithm %q (only EdDSA is permitted)", ErrInvalidConfig, c.SigningAlgorithm)
	}
	if !c.DenyByDefault {
		return fmt.Errorf("%w: deny_by_default must be true", ErrInvalidConfig)
	}
	if c.DefaultGrantTTLSeconds <= 0 || c.MaxGrantTTLSeconds <= 0 {
		return fmt.Errorf("%w: grant TTL seconds must be positive", ErrInvalidConfig)
	}
	if c.DefaultGrantTTLSeconds > c.MaxGrantTTLSeconds {
		return fmt.Errorf("%w: default_grant_ttl_seconds (%d) exceeds max_grant_ttl_seconds (%d)", ErrInvalidConfig, c.DefaultGrantTTLSeconds, c.MaxGrantTTLSeconds)
	}
	if c.MaxApprovalTTLSeconds <= 0 {
		return fmt.Errorf("%w: max_approval_ttl_seconds must be positive", ErrInvalidConfig)
	}
	if c.MaxDelegationDepth < 0 || c.MaxDelegationDepth > 5 {
		return fmt.Errorf("%w: max_delegation_depth must be between 0 and 5", ErrInvalidConfig)
	}
	if c.ClockSkewSeconds < 0 || c.ClockSkewSeconds > 60 {
		return fmt.Errorf("%w: clock_skew_seconds must be between 0 and 60", ErrInvalidConfig)
	}
	if len(c.AllowedAudiences) == 0 {
		return fmt.Errorf("%w: allowed_audiences must be non-empty", ErrInvalidConfig)
	}
	if len(c.SupportedActionTypes) == 0 {
		return fmt.Errorf("%w: supported_action_types must be non-empty", ErrInvalidConfig)
	}
	if len(c.SupportedCurrencies) == 0 {
		return fmt.Errorf("%w: supported_currencies must be non-empty", ErrInvalidConfig)
	}
	if c.Storage.Driver != "sqlite" && c.Storage.Driver != "postgres" {
		return fmt.Errorf("%w: unsupported storage driver %q (expected sqlite or postgres)", ErrInvalidConfig, c.Storage.Driver)
	}
	if strings.TrimSpace(c.Storage.DSN) == "" {
		return fmt.Errorf("%w: storage.dsn is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Redaction.Replacement) == "" {
		return fmt.Errorf("%w: redaction.replacement is required", ErrInvalidConfig)
	}
	return nil
}
