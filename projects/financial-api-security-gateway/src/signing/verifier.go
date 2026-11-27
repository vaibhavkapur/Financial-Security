package signing

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// ClientSigningKey binds a request-signing key ID to a specific client identity.
type ClientSigningKey struct {
	KeyID      string
	ClientID   string
	Algorithm  string // "Ed25519" or "HMAC-SHA256"
	Ed25519Pub ed25519.PublicKey
	HMACSecret []byte
	Revoked    bool
}

// KeyStore manages per-client request-signing keys with rotation and revocation.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*ClientSigningKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string]*ClientSigningKey)}
}

func (ks *KeyStore) AddEd25519Key(keyID, clientID string, pub ed25519.PublicKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[keyID] = &ClientSigningKey{
		KeyID:      keyID,
		ClientID:   clientID,
		Algorithm:  "Ed25519",
		Ed25519Pub: append(ed25519.PublicKey(nil), pub...),
	}
}

func (ks *KeyStore) AddHMACKey(keyID, clientID string, secret []byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[keyID] = &ClientSigningKey{
		KeyID:      keyID,
		ClientID:   clientID,
		Algorithm:  "HMAC-SHA256",
		HMACSecret: append([]byte(nil), secret...),
	}
}

func (ks *KeyStore) RevokeKey(keyID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	k, ok := ks.keys[keyID]
	if !ok {
		return fmt.Errorf("unknown request-signing key %q", keyID)
	}
	k.Revoked = true
	return nil
}

func (ks *KeyStore) GetKey(keyID string) (*ClientSigningKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[keyID]
	if !ok {
		return nil, false
	}
	cp := *k
	return &cp, true
}

// RequestVerifier validates request signatures, timestamp freshness, and nonce uniqueness.
type RequestVerifier struct {
	Config      domain.SigningConfig
	Keys        *KeyStore
	Nonces      NonceStore
	Clock       domain.Clock
	allowedAlgs map[string]bool
}

func NewRequestVerifier(cfg domain.SigningConfig, keys *KeyStore, nonces NonceStore, clock domain.Clock) *RequestVerifier {
	if clock == nil {
		clock = domain.RealClock{}
	}
	algs := make(map[string]bool, len(cfg.AllowedAlgorithms))
	for _, a := range cfg.AllowedAlgorithms {
		algs[a] = true
	}
	return &RequestVerifier{
		Config:      cfg,
		Keys:        keys,
		Nonces:      nonces,
		Clock:       clock,
		allowedAlgs: algs,
	}
}

// Verify checks timestamp window, key ownership/revocation, cryptographic signature, and replay nonce.
func (v *RequestVerifier) Verify(env domain.RequestEnvelope, clientID string) (domain.ReasonCode, string) {
	h := env.Signature
	if strings.TrimSpace(h.Signature) == "" || strings.TrimSpace(h.KeyID) == "" || strings.TrimSpace(h.Algorithm) == "" {
		return domain.ReasonSigMissing, "missing required request signature headers"
	}
	if strings.TrimSpace(h.Nonce) == "" {
		return domain.ReasonNonceMissing, "missing required X-Request-Nonce header"
	}
	if !v.allowedAlgs[h.Algorithm] {
		return domain.ReasonSigAlgRejected, fmt.Sprintf("request signing algorithm %q is not allowed", h.Algorithm)
	}

	reqTS, err := time.Parse(time.RFC3339, h.Timestamp)
	if err != nil {
		return domain.ReasonSigTimestampInvalid, "invalid X-Request-Timestamp (RFC3339 UTC required)"
	}

	now := v.Clock.Now().UTC()
	maxAge := time.Duration(v.Config.MaxRequestAgeSeconds) * time.Second
	maxFuture := time.Duration(v.Config.MaxFutureSkewSeconds) * time.Second
	if now.Sub(reqTS) > maxAge {
		return domain.ReasonSigExpired, "signed request timestamp exceeded max request age"
	}
	if reqTS.Sub(now) > maxFuture {
		return domain.ReasonSigFuture, "signed request timestamp is too far in the future"
	}

	key, ok := v.Keys.GetKey(h.KeyID)
	if !ok || (clientID != "" && key.ClientID != clientID) {
		return domain.ReasonSigKeyUnknown, fmt.Sprintf("unknown or unauthorized signing key %q", h.KeyID)
	}
	if key.Revoked {
		return domain.ReasonSigKeyRevoked, fmt.Sprintf("request signing key %q is revoked", h.KeyID)
	}
	if key.Algorithm != h.Algorithm {
		return domain.ReasonSigAlgRejected, fmt.Sprintf("header algorithm %q mismatches registered key algorithm %q", h.Algorithm, key.Algorithm)
	}

	canonical, _ := CanonicalRequestString(env.Method, env.Path, env.RawQuery, h.Timestamp, h.Nonce, h.KeyID, env.Body)
	var valid bool
	switch key.Algorithm {
	case "Ed25519":
		valid = VerifyEd25519(key.Ed25519Pub, canonical, h.Signature)
	case "HMAC-SHA256":
		valid = VerifyHMACSHA256(key.HMACSecret, canonical, h.Signature)
	}
	if !valid {
		return domain.ReasonSigInvalid, "request signature verification failed"
	}

	// Only consume nonce AFTER cryptographic verification succeeds so unauthenticated traffic cannot pollute/DoS nonce space.
	scopeKey := key.ClientID + ":" + h.Nonce
	ttl := time.Duration(v.Config.NonceTTLSeconds) * time.Second
	if v.Nonces != nil && v.Nonces.CheckAndRecord(scopeKey, now, ttl) {
		return domain.ReasonNonceReplay, "replayed request nonce rejected"
	}

	return domain.ReasonAllowed, "request signature verified"
}
