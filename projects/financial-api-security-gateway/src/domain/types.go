package domain

import "time"

const (
	SchemaVersion = "1.0.0"

	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
)

// Decision represents the binary authorization/enforcement outcome.
type Decision string

// ReasonCode identifies the exact rule or failure behind a gateway decision.
type ReasonCode string

const (
	ReasonAllowed                ReasonCode = "OK_ALLOWED"
	ReasonPolicyDefaultDeny      ReasonCode = "ERR_POLICY_DEFAULT_DENY"
	ReasonMethodUnsupported      ReasonCode = "ERR_METHOD_UNSUPPORTED"
	ReasonBodyTooLarge           ReasonCode = "ERR_BODY_TOO_LARGE"
	ReasonMTLSRequired           ReasonCode = "ERR_MTLS_REQUIRED"
	ReasonMTLSRevoked            ReasonCode = "ERR_MTLS_REVOKED"
	ReasonClientUnknown          ReasonCode = "ERR_CLIENT_UNKNOWN"
	ReasonClientRevoked          ReasonCode = "ERR_CLIENT_REVOKED"
	ReasonTokenMissing           ReasonCode = "ERR_TOKEN_MISSING"
	ReasonTokenMalformed         ReasonCode = "ERR_TOKEN_MALFORMED"
	ReasonTokenAlgRejected       ReasonCode = "ERR_TOKEN_ALG_REJECTED"
	ReasonTokenSigInvalid        ReasonCode = "ERR_TOKEN_SIG_INVALID"
	ReasonTokenKeyUnknown        ReasonCode = "ERR_TOKEN_KEY_UNKNOWN"
	ReasonTokenKeyRevoked        ReasonCode = "ERR_TOKEN_KEY_REVOKED"
	ReasonTokenExpired           ReasonCode = "ERR_TOKEN_EXPIRED"
	ReasonTokenNotYetValid       ReasonCode = "ERR_TOKEN_NOT_YET_VALID"
	ReasonTokenIssuerMismatch    ReasonCode = "ERR_TOKEN_ISSUER_MISMATCH"
	ReasonTokenAudienceMismatch  ReasonCode = "ERR_TOKEN_AUDIENCE_MISMATCH"
	ReasonTokenRevoked           ReasonCode = "ERR_TOKEN_REVOKED"
	ReasonCertTokenMismatch      ReasonCode = "ERR_CERT_TOKEN_MISMATCH"
	ReasonSubjectCertMismatch    ReasonCode = "ERR_SUBJECT_CERT_MISMATCH"
	ReasonSigMissing             ReasonCode = "ERR_SIG_MISSING"
	ReasonSigAlgRejected         ReasonCode = "ERR_SIG_ALG_REJECTED"
	ReasonSigKeyUnknown          ReasonCode = "ERR_SIG_KEY_UNKNOWN"
	ReasonSigKeyRevoked          ReasonCode = "ERR_SIG_KEY_REVOKED"
	ReasonSigTimestampInvalid    ReasonCode = "ERR_SIG_TIMESTAMP_INVALID"
	ReasonSigExpired             ReasonCode = "ERR_SIG_EXPIRED"
	ReasonSigFuture              ReasonCode = "ERR_SIG_FUTURE"
	ReasonSigInvalid             ReasonCode = "ERR_SIG_INVALID"
	ReasonNonceMissing           ReasonCode = "ERR_NONCE_MISSING"
	ReasonNonceReplay            ReasonCode = "ERR_NONCE_REPLAY"
	ReasonRoleForbidden          ReasonCode = "ERR_ROLE_FORBIDDEN"
	ReasonScopeInsufficient      ReasonCode = "ERR_SCOPE_INSUFFICIENT"
	ReasonScopeNotGrantedToActor ReasonCode = "ERR_SCOPE_NOT_GRANTED_TO_CLIENT"
	ReasonRateLimited            ReasonCode = "ERR_RATE_LIMITED"
	ReasonUpstreamTimeout        ReasonCode = "ERR_UPSTREAM_TIMEOUT"
	ReasonUpstreamUnavailable    ReasonCode = "ERR_UPSTREAM_UNAVAILABLE"
)

// GatewayConfig is the versioned root configuration contract.
type GatewayConfig struct {
	SchemaVersion         string          `json:"schema_version"`
	Environment           string          `json:"environment"`
	ListenAddr            string          `json:"listen_addr"`
	UpstreamURL           string          `json:"upstream_url"`
	UpstreamTimeoutMs     int             `json:"upstream_timeout_ms"`
	DenyByDefault         bool            `json:"deny_by_default"`
	RequireMTLS           bool            `json:"require_mtls"`
	RequireCertBoundToken bool            `json:"require_cert_bound_token"`
	OIDC                  OIDCConfig      `json:"oidc"`
	Signing               SigningConfig   `json:"signing"`
	RateLimit             RateLimitConfig `json:"rate_limit"`
	Audit                 AuditConfig     `json:"audit"`
}

// OIDCConfig configures mock OIDC/JWT validation constraints.
type OIDCConfig struct {
	Issuer              string   `json:"issuer"`
	Audience            string   `json:"audience"`
	AllowedAlgorithms   []string `json:"allowed_algorithms"`
	MaxClockSkewSeconds int      `json:"max_clock_skew_seconds"`
}

// SigningConfig configures request-signing and replay-prevention constraints.
type SigningConfig struct {
	Required             bool     `json:"required"`
	MaxRequestAgeSeconds int      `json:"max_request_age_seconds"`
	MaxFutureSkewSeconds int      `json:"max_future_skew_seconds"`
	NonceTTLSeconds      int      `json:"nonce_ttl_seconds"`
	MaxNonceEntries      int      `json:"max_nonce_entries"`
	AllowedAlgorithms    []string `json:"allowed_algorithms"`
}

// RateLimitConfig defines fallback token-bucket parameters.
type RateLimitConfig struct {
	DefaultRequestsPerSecond float64 `json:"default_requests_per_second"`
	DefaultBurst             int     `json:"default_burst"`
}

// AuditConfig defines log redaction and body bounds.
type AuditConfig struct {
	RedactHeaders  []string `json:"redact_headers"`
	RedactJSONKeys []string `json:"redact_json_keys"`
	MaxBodyBytes   int64    `json:"max_body_bytes"`
}

// PolicySet defines deny-by-default authorization rules.
type PolicySet struct {
	SchemaVersion string       `json:"schema_version"`
	PolicyVersion string       `json:"policy_version"`
	DefaultEffect string       `json:"default_effect"`
	Rules         []PolicyRule `json:"rules"`
}

// PolicyRule defines per-resource authorization and protection requirements.
type PolicyRule struct {
	ID               string   `json:"id"`
	Method           string   `json:"method"`
	PathPattern      string   `json:"path_pattern"`
	RequiredScopes   []string `json:"required_scopes"`
	AllowedRoles     []string `json:"allowed_roles"`
	RequireMTLS      bool     `json:"require_mtls"`
	RequireSignature bool     `json:"require_signature"`
	RateLimitRPS     float64  `json:"rate_limit_rps"`
	RateLimitBurst   int      `json:"rate_limit_burst"`
	MaxBodyBytes     int64    `json:"max_body_bytes"`
}

// ClientRegistry holds authorized mock client identities.
type ClientRegistry struct {
	SchemaVersion string           `json:"schema_version"`
	Clients       []ClientIdentity `json:"clients"`
}

// ClientIdentity represents a registered synthetic API caller.
type ClientIdentity struct {
	ClientID      string   `json:"client_id"`
	Role          string   `json:"role"`
	SPIFFEID      string   `json:"spiffe_id"`
	AllowedScopes []string `json:"allowed_scopes"`
	Status        string   `json:"status"` // "active" or "revoked"
	Description   string   `json:"description"`
}

// PeerCertInfo captures validated mTLS peer certificate metadata.
type PeerCertInfo struct {
	Present          bool   `json:"present"`
	CommonName       string `json:"common_name"`
	SPIFFEID         string `json:"spiffe_id"`
	SerialHex        string `json:"serial_hex"`
	ThumbprintSHA256 string `json:"thumbprint_sha256"`
	IssuerCN         string `json:"issuer_cn"`
}

// TokenClaims captures validated OIDC JWT claims.
type TokenClaims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       string   `json:"aud"`
	JWTID          string   `json:"jti"`
	IssuedAt       int64    `json:"iat"`
	NotBefore      int64    `json:"nbf"`
	ExpiresAt      int64    `json:"exp"`
	Scopes         []string `json:"scopes"`
	CertThumbprint string   `json:"cnf_x5t_s256,omitempty"`
	KeyID          string   `json:"kid"`
	Algorithm      string   `json:"alg"`
}

// SignatureHeaders captures request-integrity headers sent by a caller.
type SignatureHeaders struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// RequestEnvelope is the transport-independent input to the pure security evaluator.
type RequestEnvelope struct {
	RequestID  string              `json:"request_id"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	RawQuery   string              `json:"raw_query"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	BearerAuth string              `json:"-"` // Never serialize raw token
	PeerCert   PeerCertInfo        `json:"peer_cert"`
	Signature  SignatureHeaders    `json:"signature"`
	ReceivedAt time.Time           `json:"received_at"`
}

// EvaluationResult is the deterministic output of the core gateway evaluator.
type EvaluationResult struct {
	RequestID         string       `json:"request_id"`
	Decision          Decision     `json:"decision"`
	ReasonCode        ReasonCode   `json:"reason_code"`
	HTTPStatus        int          `json:"http_status"`
	Message           string       `json:"message"`
	PolicyRuleID      string       `json:"policy_rule_id,omitempty"`
	ClientID          string       `json:"client_id,omitempty"`
	ClientRole        string       `json:"client_role,omitempty"`
	TokenJTI          string       `json:"token_jti,omitempty"`
	CertThumbprint    string       `json:"cert_thumbprint,omitempty"`
	GrantedScopes     []string     `json:"granted_scopes,omitempty"`
	RateLimitRem      int          `json:"rate_limit_remaining,omitempty"`
	RetryAfterSeconds int          `json:"retry_after_seconds,omitempty"`
	MatchedRule       *PolicyRule  `json:"-"`
}

// AuditEvent is the redacted, structured security event emitted per request.
type AuditEvent struct {
	EventID         string              `json:"event_id"`
	SchemaVersion   string              `json:"schema_version"`
	Timestamp       string              `json:"timestamp"`
	RequestID       string              `json:"request_id"`
	ClientID        string              `json:"client_id"`
	ClientRole      string              `json:"client_role,omitempty"`
	CertThumbprint  string              `json:"cert_thumbprint,omitempty"`
	CertSerialHex   string              `json:"cert_serial_hex,omitempty"`
	TokenJTI        string              `json:"token_jti,omitempty"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	PolicyRuleID    string              `json:"policy_rule_id,omitempty"`
	Decision        Decision            `json:"decision"`
	ReasonCode      ReasonCode          `json:"reason_code"`
	HTTPStatus      int                 `json:"http_status"`
	LatencyUs       int64               `json:"latency_us"`
	RedactedHeaders map[string][]string `json:"redacted_headers"`
	RedactedCount   int                 `json:"redacted_count"`
	Message         string              `json:"message"`
}

// ErrorResponse is the client-facing structured JSON error contract.
type ErrorResponse struct {
	SchemaVersion string     `json:"schema_version"`
	RequestID     string     `json:"request_id"`
	ErrorCode     ReasonCode `json:"error_code"`
	Message       string     `json:"message"`
	Timestamp     string     `json:"timestamp"`
}
