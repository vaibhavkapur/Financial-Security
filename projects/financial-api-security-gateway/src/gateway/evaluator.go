package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
	"github.com/financial-security/financial-api-security-gateway/src/oidc"
	"github.com/financial-security/financial-api-security-gateway/src/pki"
	"github.com/financial-security/financial-api-security-gateway/src/policy"
	"github.com/financial-security/financial-api-security-gateway/src/ratelimit"
	"github.com/financial-security/financial-api-security-gateway/src/signing"
)

// Evaluator isolates the core security state machine from HTTP/TLS transport I/O.
type Evaluator struct {
	Config          domain.GatewayConfig
	PolicyEngine    *policy.Engine
	TokenVerifier   *oidc.Verifier
	RequestVerifier *signing.RequestVerifier
	RateLimiter     ratelimit.Limiter
	CertRevocations pki.CertRevocationStore
}

// Evaluate runs the deterministic deny-by-default security verification pipeline:
//  1. Method & body size validation
//  2. Policy route match (deny-by-default)
//  3. mTLS client cert presence & live revocation check
//  4. OIDC JWT validation (signature, alg, iss, aud, exp/nbf, jti revocation, cnf cert thumbprint)
//  5. Client registry lookup, status check & mTLS CN == token sub binding
//  6. Canonical request signature, timestamp freshness & replay nonce verification
//  7. Per-resource role & scope authorization (with client scope ceiling)
//  8. Per-client & per-resource rate limiting
func (e *Evaluator) Evaluate(env domain.RequestEnvelope) domain.EvaluationResult {
	res := domain.EvaluationResult{
		RequestID:      env.RequestID,
		Decision:       domain.DecisionDeny,
		CertThumbprint: env.PeerCert.ThumbprintSHA256,
	}

	if !domain.IsSupportedMethod(env.Method) {
		res.ReasonCode = domain.ReasonMethodUnsupported
		res.HTTPStatus = http.StatusMethodNotAllowed
		res.Message = fmt.Sprintf("HTTP method %q is not supported", env.Method)
		return res
	}

	if int64(len(env.Body)) > e.Config.Audit.MaxBodyBytes {
		res.ReasonCode = domain.ReasonBodyTooLarge
		res.HTTPStatus = http.StatusRequestEntityTooLarge
		res.Message = fmt.Sprintf("request body exceeds global limit of %d bytes", e.Config.Audit.MaxBodyBytes)
		return res
	}

	// Deny-by-default policy matching first so unknown routes are never exposed.
	rule := e.PolicyEngine.MatchRule(env.Method, env.Path)
	if rule == nil {
		res.ReasonCode = domain.ReasonPolicyDefaultDeny
		res.HTTPStatus = http.StatusForbidden
		res.Message = "request denied by default: no authorization policy matches route"
		return res
	}
	res.PolicyRuleID = rule.ID
	res.MatchedRule = rule

	if rule.MaxBodyBytes >= 0 && int64(len(env.Body)) > rule.MaxBodyBytes {
		if !(rule.MaxBodyBytes == 0 && len(env.Body) == 0) {
			res.ReasonCode = domain.ReasonBodyTooLarge
			res.HTTPStatus = http.StatusRequestEntityTooLarge
			res.Message = fmt.Sprintf("request body exceeds policy limit of %d bytes", rule.MaxBodyBytes)
			return res
		}
	}

	// mTLS verification & live revocation check (covers kept-alive connections after revocation).
	if e.Config.RequireMTLS || rule.RequireMTLS {
		if !env.PeerCert.Present || strings.TrimSpace(env.PeerCert.CommonName) == "" {
			res.ReasonCode = domain.ReasonMTLSRequired
			res.HTTPStatus = http.StatusUnauthorized
			res.Message = "verified mTLS client certificate is required"
			return res
		}
		if e.CertRevocations != nil && env.PeerCert.SerialHex != "" && e.CertRevocations.IsRevoked(env.PeerCert.SerialHex) {
			res.ReasonCode = domain.ReasonMTLSRevoked
			res.HTTPStatus = http.StatusUnauthorized
			res.Message = "mTLS client certificate has been revoked"
			return res
		}
	}

	// OIDC Bearer JWT verification.
	claims, tokenReason, err := e.TokenVerifier.Verify(env.BearerAuth, env.PeerCert.ThumbprintSHA256)
	if err != nil {
		res.ReasonCode = tokenReason
		res.HTTPStatus = http.StatusUnauthorized
		res.Message = err.Error()
		return res
	}
	res.TokenJTI = claims.JWTID
	res.ClientID = claims.Subject

	// Bind mTLS certificate identity to JWT subject when mTLS is active.
	if env.PeerCert.Present && env.PeerCert.CommonName != claims.Subject {
		res.ReasonCode = domain.ReasonSubjectCertMismatch
		res.HTTPStatus = http.StatusForbidden
		res.Message = "token subject does not match mTLS client certificate identity"
		return res
	}

	// Client registry verification.
	client, ok := e.PolicyEngine.LookupClient(claims.Subject)
	if !ok {
		res.ReasonCode = domain.ReasonClientUnknown
		res.HTTPStatus = http.StatusForbidden
		res.Message = fmt.Sprintf("unknown client identity %q", claims.Subject)
		return res
	}
	res.ClientRole = client.Role
	if client.Status != "active" {
		res.ReasonCode = domain.ReasonClientRevoked
		res.HTTPStatus = http.StatusForbidden
		res.Message = fmt.Sprintf("client %q is revoked", client.ClientID)
		return res
	}

	// Per-resource role and scope authorization (before consuming nonces or rate-limit tokens on unauthorized scope escalations,
	// or wait: verifying request signature before policy prevents unauthenticated attackers from probing policies, while authenticating
	// via mTLS + JWT already authenticated the caller! Let's verify request integrity right here so tampered/replayed signed requests
	// are rejected immediately regardless of downstream policy).
	if e.Config.Signing.Required || rule.RequireSignature {
		sigReason, sigMsg := e.RequestVerifier.Verify(env, client.ClientID)
		if sigReason != domain.ReasonAllowed {
			res.ReasonCode = sigReason
			if sigReason == domain.ReasonNonceReplay {
				res.HTTPStatus = http.StatusConflict
			} else {
				res.HTTPStatus = http.StatusUnauthorized
			}
			res.Message = sigMsg
			return res
		}
	}

	// Per-resource role & scope authorization.
	authReason, authMsg := e.PolicyEngine.Authorize(client, claims, rule)
	if authReason != domain.ReasonAllowed {
		res.ReasonCode = authReason
		res.HTTPStatus = http.StatusForbidden
		res.Message = authMsg
		return res
	}

	// Per-client & per-resource rate limiting.
	if e.RateLimiter != nil {
		rps := rule.RateLimitRPS
		burst := rule.RateLimitBurst
		if rps <= 0 {
			rps = e.Config.RateLimit.DefaultRequestsPerSecond
		}
		if burst <= 0 {
			burst = e.Config.RateLimit.DefaultBurst
		}
		bucketKey := client.ClientID + ":" + rule.ID
		rl := e.RateLimiter.Allow(bucketKey, rps, burst)
		res.RateLimitRem = rl.Remaining
		if !rl.Allowed {
			res.ReasonCode = domain.ReasonRateLimited
			res.HTTPStatus = http.StatusTooManyRequests
			res.RetryAfterSeconds = rl.RetryAfterSeconds
			res.Message = "rate limit exceeded for client and resource"
			return res
		}
	}

	res.Decision = domain.DecisionAllow
	res.ReasonCode = domain.ReasonAllowed
	res.HTTPStatus = http.StatusOK
	res.Message = "request authorized"
	res.GrantedScopes = claims.Scopes
	return res
}
