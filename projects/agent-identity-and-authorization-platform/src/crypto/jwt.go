package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

// GrantClaims encodes bounded delegation claims inside an RFC 7519 JWT signed with EdDSA (RFC 8037).
type GrantClaims struct {
	jwt.RegisteredClaims
	ParentGrantID         string               `json:"parent_grant_id,omitempty"`
	RootGrantID           string               `json:"root_grant_id"`
	DelegationDepth       int                  `json:"delegation_depth"`
	CanDelegate           bool                 `json:"can_delegate"`
	DelegatorID           string               `json:"delegator_id"`
	TenantID              string               `json:"tenant_id"`
	Scopes                []domain.Scope       `json:"scopes"`
	AllowedCounterparties []string             `json:"allowed_counterparties,omitempty"`
	SpendingLimit         domain.SpendingLimit `json:"spending_limit"`
}

// GrantSigner issues signed EdDSA JWTs for validated DelegationGrants.
type GrantSigner struct {
	Key KeyPair
}

// SignGrant produces a compact JWS (JWT) signed with EdDSA (Ed25519).
func (s GrantSigner) SignGrant(g domain.DelegationGrant) (string, error) {
	if len(s.Key.PrivateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("signer missing valid Ed25519 private key")
	}
	claims := GrantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.IssuerID,
			Subject:   g.ActorID,
			Audience:  jwt.ClaimStrings(g.Audiences),
			ID:        g.GrantID,
			IssuedAt:  jwt.NewNumericDate(g.IssuedAtUTC.UTC().Truncate(time.Second)),
			NotBefore: jwt.NewNumericDate(g.NotBeforeUTC.UTC().Truncate(time.Second)),
			ExpiresAt: jwt.NewNumericDate(g.ExpiresAtUTC.UTC().Truncate(time.Second)),
		},
		ParentGrantID:         g.ParentGrantID,
		RootGrantID:           g.RootGrantID,
		DelegationDepth:       g.DelegationDepth,
		CanDelegate:           g.CanDelegate,
		DelegatorID:           g.DelegatorID,
		TenantID:              g.TenantID,
		Scopes:                g.Scopes,
		AllowedCounterparties: g.AllowedCounterparties,
		SpendingLimit:         g.SpendingLimit,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if s.Key.KeyID != "" {
		tok.Header["kid"] = s.Key.KeyID
	}
	tok.Header["typ"] = "aiap+jwt"
	return tok.SignedString(s.Key.PrivateKey)
}

// GrantVerifier verifies EdDSA JWT grants with strict algorithm pinning and deterministic time.
type GrantVerifier struct {
	IssuerID         string
	PublicKeysByKID  map[string]ed25519.PublicKey
	DefaultPublicKey ed25519.PublicKey
	ClockSkewSeconds int64
}

// VerifyGrant validates the JWT header alg, Ed25519 signature, issuer, nbf, exp, and required claims.
// Returns structured DomainError codes (ERR_TOKEN_INVALID_ALG, ERR_TOKEN_INVALID_SIG, ERR_GRANT_EXPIRED, etc.).
func (v GrantVerifier) VerifyGrant(rawToken string, now time.Time) (*GrantClaims, error) {
	if rawToken == "" {
		return nil, domain.NewDomainError(domain.ReasonTokenMalformed, "grant token is empty")
	}
	claims := &GrantClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(v.IssuerID),
		jwt.WithTimeFunc(func() time.Time { return now.UTC().Truncate(time.Second) }),
		jwt.WithLeeway(time.Duration(v.ClockSkewSeconds)*time.Second),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)

	tok, err := parser.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidAlg, "signing algorithm %v is not permitted (expected EdDSA)", t.Header["alg"])
		}
		if kid, ok := t.Header["kid"].(string); ok && kid != "" && len(v.PublicKeysByKID) > 0 {
			if pub, found := v.PublicKeysByKID[kid]; found {
				return pub, nil
			}
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidSig, "unknown signing key id %q", kid)
		}
		if len(v.DefaultPublicKey) != ed25519.PublicKeySize {
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidSig, "verifier has no trusted Ed25519 public key")
		}
		return v.DefaultPublicKey, nil
	})
	if err != nil {
		var de *domain.DomainError
		if errors.As(err, &de) {
			return nil, de
		}
		switch {
		case strings.Contains(err.Error(), "signing method"):
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidAlg, "token header signing algorithm rejected: %v", err)
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, domain.NewDomainError(domain.ReasonGrantExpired, "signed grant token is expired")
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, domain.NewDomainError(domain.ReasonGrantNotYetValid, "signed grant token is not yet valid")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidSig, "signed grant token signature verification failed")
		case errors.Is(err, jwt.ErrTokenUnverifiable):
			return nil, domain.NewDomainError(domain.ReasonTokenInvalidAlg, "token header algorithm rejected or unverifiable: %v", err)
		default:
			return nil, domain.NewDomainError(domain.ReasonTokenMalformed, "grant token invalid: %v", err)
		}
	}
	if !tok.Valid {
		return nil, domain.NewDomainError(domain.ReasonTokenMalformed, "grant token marked invalid")
	}
	if claims.ID == "" || claims.Subject == "" || claims.DelegatorID == "" || claims.TenantID == "" {
		return nil, domain.NewDomainError(domain.ReasonTokenMalformed, "grant token missing required identity claims")
	}
	return claims, nil
}
