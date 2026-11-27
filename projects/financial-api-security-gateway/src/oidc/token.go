package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// TokenRevocationStore tracks revoked JWT IDs (jti).
type TokenRevocationStore interface {
	RevokeJTI(jti string, expiresAt time.Time)
	IsRevoked(jti string) bool
	Count() int
}

// MemoryTokenRevocationStore is a thread-safe in-memory JTI revocation store.
type MemoryTokenRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

func NewMemoryTokenRevocationStore() *MemoryTokenRevocationStore {
	return &MemoryTokenRevocationStore{revoked: make(map[string]time.Time)}
}

func (s *MemoryTokenRevocationStore) RevokeJTI(jti string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = expiresAt.UTC()
}

func (s *MemoryTokenRevocationStore) IsRevoked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[jti]
	return ok
}

func (s *MemoryTokenRevocationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.revoked)
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtPayload struct {
	Iss   string            `json:"iss"`
	Sub   string            `json:"sub"`
	Aud   any               `json:"aud"`
	Jti   string            `json:"jti"`
	Iat   int64             `json:"iat"`
	Nbf   int64             `json:"nbf"`
	Exp   int64             `json:"exp"`
	Scope string            `json:"scope"`
	Cnf   map[string]string `json:"cnf,omitempty"`
}

// MintParams defines claims for minting a mock OIDC access token.
type MintParams struct {
	Issuer         string
	Subject        string
	Audience       string
	JWTID          string
	Scopes         []string
	CertThumbprint string
	IssuedAt       time.Time
	NotBefore      time.Time
	ExpiresAt      time.Time
	KeyID          string // optional: uses active key if empty
}

// Issuer mints signed RFC 7519 JWTs backed by a KeyRing.
type Issuer struct {
	KeyRing *KeyRing
}

func NewIssuer(kr *KeyRing) *Issuer {
	return &Issuer{KeyRing: kr}
}

// MintToken creates and signs a JWT using the specified or active key.
func (is *Issuer) MintToken(p MintParams) (string, error) {
	var key *SigningKey
	var err error
	if p.KeyID != "" {
		var ok bool
		key, ok = is.KeyRing.GetKey(p.KeyID)
		if !ok {
			return "", fmt.Errorf("unknown signing key %q", p.KeyID)
		}
	} else {
		key, err = is.KeyRing.ActiveKey()
		if err != nil {
			return "", err
		}
	}
	if key.PrivateKey == nil {
		return "", fmt.Errorf("signing key %q has no private material", key.KID)
	}

	hdr := jwtHeader{Alg: key.Algorithm, Typ: "JWT", Kid: key.KID}
	payload := jwtPayload{
		Iss:   p.Issuer,
		Sub:   p.Subject,
		Aud:   p.Audience,
		Jti:   p.JWTID,
		Iat:   p.IssuedAt.UTC().Unix(),
		Nbf:   p.NotBefore.UTC().Unix(),
		Exp:   p.ExpiresAt.UTC().Unix(),
		Scope: strings.Join(p.Scopes, " "),
	}
	if p.CertThumbprint != "" {
		payload.Cnf = map[string]string{"x5t#S256": p.CertThumbprint}
	}
	return signJWT(hdr, payload, key)
}

func signJWT(hdr jwtHeader, payload jwtPayload, key *SigningKey) (string, error) {
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	payBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payBytes)

	var sig []byte
	switch key.Algorithm {
	case "EdDSA":
		priv, ok := key.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("expected ed25519 private key")
		}
		sig = ed25519.Sign(priv, []byte(signingInput))
	case "ES256":
		priv, ok := key.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("expected ecdsa private key")
		}
		sum := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			return "", err
		}
		sig = make([]byte, 64)
		copy(sig[0:32], pad32(r.Bytes()))
		copy(sig[32:64], pad32(s.Bytes()))
	default:
		return "", fmt.Errorf("unsupported algorithm %q", key.Algorithm)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verifier strictly validates JWT tokens against OIDC configuration, JWKS, clock, revocation, and cert thumbprint.
type Verifier struct {
	Config                domain.OIDCConfig
	RequireCertBoundToken bool
	KeyRing               *KeyRing
	Revocations           TokenRevocationStore
	Clock                 domain.Clock
	allowedAlgs           map[string]bool
}

func NewVerifier(cfg domain.OIDCConfig, requireCertBound bool, kr *KeyRing, rev TokenRevocationStore, clock domain.Clock) *Verifier {
	if clock == nil {
		clock = domain.RealClock{}
	}
	algs := make(map[string]bool, len(cfg.AllowedAlgorithms))
	for _, a := range cfg.AllowedAlgorithms {
		algs[a] = true
	}
	return &Verifier{
		Config:                cfg,
		RequireCertBoundToken: requireCertBound,
		KeyRing:               kr,
		Revocations:           rev,
		Clock:                 clock,
		allowedAlgs:           algs,
	}
}

// Verify parses and strictly validates a bearer JWT.
func (v *Verifier) Verify(rawToken string, peerThumbprint string) (domain.TokenClaims, domain.ReasonCode, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return domain.TokenClaims{}, domain.ReasonTokenMissing, errors.New("missing bearer token")
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return domain.TokenClaims{}, domain.ReasonTokenMalformed, errors.New("malformed JWT structure")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return domain.TokenClaims{}, domain.ReasonTokenMalformed, errors.New("invalid base64url JWT header")
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return domain.TokenClaims{}, domain.ReasonTokenMalformed, errors.New("invalid JSON JWT header")
	}
	if !v.allowedAlgs[hdr.Alg] {
		return domain.TokenClaims{}, domain.ReasonTokenAlgRejected, fmt.Errorf("rejected JWT algorithm %q", hdr.Alg)
	}
	if strings.TrimSpace(hdr.Kid) == "" {
		return domain.TokenClaims{}, domain.ReasonTokenKeyUnknown, errors.New("missing JWT kid header")
	}
	key, ok := v.KeyRing.GetKey(hdr.Kid)
	if !ok {
		return domain.TokenClaims{}, domain.ReasonTokenKeyUnknown, fmt.Errorf("unknown JWT kid %q", hdr.Kid)
	}
	if key.Revoked {
		return domain.TokenClaims{}, domain.ReasonTokenKeyRevoked, fmt.Errorf("JWT signing key %q has been revoked", hdr.Kid)
	}
	if key.Algorithm != hdr.Alg {
		return domain.TokenClaims{}, domain.ReasonTokenAlgRejected, fmt.Errorf("JWT alg %q does not match key alg %q", hdr.Alg, key.Algorithm)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) == 0 {
		return domain.TokenClaims{}, domain.ReasonTokenSigInvalid, errors.New("invalid JWT signature encoding")
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyJWTSignature(key, signingInput, sigBytes) {
		return domain.TokenClaims{}, domain.ReasonTokenSigInvalid, errors.New("JWT cryptographic signature verification failed")
	}

	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return domain.TokenClaims{}, domain.ReasonTokenMalformed, errors.New("invalid base64url JWT payload")
	}
	var payload jwtPayload
	if err := json.Unmarshal(payBytes, &payload); err != nil {
		return domain.TokenClaims{}, domain.ReasonTokenMalformed, errors.New("invalid JSON JWT payload")
	}

	if payload.Iss != v.Config.Issuer {
		return domain.TokenClaims{}, domain.ReasonTokenIssuerMismatch, fmt.Errorf("issuer %q does not match expected %q", payload.Iss, v.Config.Issuer)
	}
	audMatched, audStr := matchAudience(payload.Aud, v.Config.Audience)
	if !audMatched {
		return domain.TokenClaims{}, domain.ReasonTokenAudienceMismatch, fmt.Errorf("audience does not match expected %q", v.Config.Audience)
	}

	nowUnix := v.Clock.Now().UTC().Unix()
	skew := int64(v.Config.MaxClockSkewSeconds)
	if payload.Exp == 0 || nowUnix > payload.Exp+skew {
		return domain.TokenClaims{}, domain.ReasonTokenExpired, errors.New("token has expired")
	}
	if payload.Nbf > 0 && nowUnix+skew < payload.Nbf {
		return domain.TokenClaims{}, domain.ReasonTokenNotYetValid, errors.New("token is not yet valid")
	}

	if payload.Jti != "" && v.Revocations != nil && v.Revocations.IsRevoked(payload.Jti) {
		return domain.TokenClaims{}, domain.ReasonTokenRevoked, fmt.Errorf("token jti %q is revoked", payload.Jti)
	}

	boundThumbprint := ""
	if payload.Cnf != nil {
		boundThumbprint = payload.Cnf["x5t#S256"]
	}
	if v.RequireCertBoundToken {
		if boundThumbprint == "" || peerThumbprint == "" || boundThumbprint != peerThumbprint {
			return domain.TokenClaims{}, domain.ReasonCertTokenMismatch, errors.New("token certificate thumbprint binding mismatch")
		}
	} else if boundThumbprint != "" && peerThumbprint != "" && boundThumbprint != peerThumbprint {
		return domain.TokenClaims{}, domain.ReasonCertTokenMismatch, errors.New("token certificate thumbprint binding mismatch")
	}

	var scopes []string
	for _, s := range strings.Fields(payload.Scope) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}

	claims := domain.TokenClaims{
		Issuer:         payload.Iss,
		Subject:        payload.Sub,
		Audience:       audStr,
		JWTID:          payload.Jti,
		IssuedAt:       payload.Iat,
		NotBefore:      payload.Nbf,
		ExpiresAt:      payload.Exp,
		Scopes:         scopes,
		CertThumbprint: boundThumbprint,
		KeyID:          hdr.Kid,
		Algorithm:      hdr.Alg,
	}
	return claims, domain.ReasonAllowed, nil
}

func verifyJWTSignature(key *SigningKey, signingInput string, sig []byte) bool {
	switch key.Algorithm {
	case "EdDSA":
		pub, ok := key.PublicKey.(ed25519.PublicKey)
		if !ok || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(pub, []byte(signingInput), sig)
	case "ES256":
		pub, ok := key.PublicKey.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		sum := sha256.Sum256([]byte(signingInput))
		return ecdsa.Verify(pub, sum[:], r, s)
	default:
		return false
	}
}

func matchAudience(aud any, expected string) (bool, string) {
	switch a := aud.(type) {
	case string:
		return a == expected, a
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == expected {
				return true, s
			}
		}
		return false, ""
	default:
		return false, ""
	}
}
