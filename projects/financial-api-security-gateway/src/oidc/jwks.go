package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// SigningKey represents an asymmetric OIDC signing/verification key in the KeyRing.
type SigningKey struct {
	KID        string
	Algorithm  string // "EdDSA" or "ES256"
	PublicKey  crypto.PublicKey
	PrivateKey crypto.Signer
	Active     bool
	Revoked    bool
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// JWK is a public-only RFC 7517 JSON Web Key representation.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a public-only RFC 7517 JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyRing manages OIDC signing keys with rotation and revocation support.
type KeyRing struct {
	mu        sync.RWMutex
	keys      map[string]*SigningKey
	activeKID string
}

func NewKeyRing() *KeyRing {
	return &KeyRing{keys: make(map[string]*SigningKey)}
}

// AddEd25519Key generates or registers an Ed25519 key (EdDSA).
func (kr *KeyRing) AddEd25519Key(kid string, pub ed25519.PublicKey, priv ed25519.PrivateKey, makeActive bool, now time.Time) (*SigningKey, error) {
	if priv == nil && pub == nil {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
	} else if pub == nil && priv != nil {
		pub = priv.Public().(ed25519.PublicKey)
	}
	k := &SigningKey{
		KID:        kid,
		Algorithm:  "EdDSA",
		PublicKey:  pub,
		PrivateKey: priv,
		Active:     makeActive,
		CreatedAt:  now.UTC(),
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if makeActive {
		for _, existing := range kr.keys {
			existing.Active = false
		}
		kr.activeKID = kid
	}
	kr.keys[kid] = k
	return k, nil
}

// AddES256Key generates or registers an ECDSA P-256 key (ES256).
func (kr *KeyRing) AddES256Key(kid string, priv *ecdsa.PrivateKey, makeActive bool, now time.Time) (*SigningKey, error) {
	if priv == nil {
		var err error
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate es256 key: %w", err)
		}
	}
	k := &SigningKey{
		KID:        kid,
		Algorithm:  "ES256",
		PublicKey:  &priv.PublicKey,
		PrivateKey: priv,
		Active:     makeActive,
		CreatedAt:  now.UTC(),
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if makeActive {
		for _, existing := range kr.keys {
			existing.Active = false
		}
		kr.activeKID = kid
	}
	kr.keys[kid] = k
	return k, nil
}

// RotateToNewEd25519Key adds a new active Ed25519 key while leaving previous non-revoked keys verifiable during overlap.
func (kr *KeyRing) RotateToNewEd25519Key(newKID string, now time.Time) (*SigningKey, error) {
	return kr.AddEd25519Key(newKID, nil, nil, true, now)
}

// RevokeKey marks a key as revoked so any tokens signed with it are immediately rejected.
func (kr *KeyRing) RevokeKey(kid string, now time.Time) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	k, ok := kr.keys[kid]
	if !ok {
		return fmt.Errorf("unknown kid %q", kid)
	}
	t := now.UTC()
	k.Revoked = true
	k.Active = false
	k.RevokedAt = &t
	if kr.activeKID == kid {
		kr.activeKID = ""
	}
	return nil
}

// ActiveKey returns the currently active signing key.
func (kr *KeyRing) ActiveKey() (*SigningKey, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.activeKID == "" {
		return nil, fmt.Errorf("no active signing key")
	}
	k, ok := kr.keys[kr.activeKID]
	if !ok || k.Revoked {
		return nil, fmt.Errorf("active signing key %q unavailable", kr.activeKID)
	}
	return k, nil
}

// GetKey retrieves a key by kid along with its revocation state.
func (kr *KeyRing) GetKey(kid string) (*SigningKey, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	k, ok := kr.keys[kid]
	if !ok {
		return nil, false
	}
	copyKey := *k
	return &copyKey, true
}

// PublicJWKS returns public-only non-revoked keys in RFC 7517 JWKS format.
func (kr *KeyRing) PublicJWKS() JWKS {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, len(kr.keys))}
	for _, k := range kr.keys {
		if k.Revoked {
			continue
		}
		switch pub := k.PublicKey.(type) {
		case ed25519.PublicKey:
			out.Keys = append(out.Keys, JWK{
				Kty: "OKP",
				Crv: "Ed25519",
				Alg: "EdDSA",
				Use: "sig",
				Kid: k.KID,
				X:   base64.RawURLEncoding.EncodeToString(pub),
			})
		case *ecdsa.PublicKey:
			out.Keys = append(out.Keys, JWK{
				Kty: "EC",
				Crv: "P-256",
				Alg: "ES256",
				Use: "sig",
				Kid: k.KID,
				X:   base64.RawURLEncoding.EncodeToString(pad32(pub.X.Bytes())),
				Y:   base64.RawURLEncoding.EncodeToString(pad32(pub.Y.Bytes())),
			})
		}
	}
	return out
}

// JWKSJSON serializes the public JWKS document.
func (kr *KeyRing) JWKSJSON() ([]byte, error) {
	return json.MarshalIndent(kr.PublicJWKS(), "", "  ")
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
