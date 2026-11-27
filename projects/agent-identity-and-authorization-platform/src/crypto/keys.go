package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

// KeyPair holds an Ed25519 key pair for synthetic signing and verification.
type KeyPair struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a fresh random Ed25519 key pair.
func GenerateKeyPair(keyID string) (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("ed25519 keygen failed: %w", err)
	}
	return KeyPair{KeyID: keyID, PublicKey: pub, PrivateKey: priv}, nil
}

// DeterministicFixtureKeyPair derives a reproducible synthetic Ed25519 key pair from a seed label.
// FOR OFFLINE FIXTURES AND TESTS ONLY — never use deterministic seeds for production keys.
func DeterministicFixtureKeyPair(keyID string, seedLabel string) KeyPair {
	seed := sha256.Sum256([]byte("aiap.synthetic.fixture.key.v1:" + seedLabel))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return KeyPair{KeyID: keyID, PublicKey: pub, PrivateKey: priv}
}

// PublicKeyBase64 returns standard base64 of the 32-byte Ed25519 public key.
func (kp KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey)
}

// JWK represents an RFC 7517 / RFC 8037 OKP Ed25519 public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// PublicJWK exports the public key in RFC 8037 JWK format.
func (kp KeyPair) PublicJWK() JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		Use: "sig",
		Kid: kp.KeyID,
		X:   base64.RawURLEncoding.EncodeToString(kp.PublicKey),
	}
}

// DecodePublicKeyBase64 parses a standard base64-encoded 32-byte Ed25519 public key.
func DecodePublicKeyBase64(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// SignApproval signs an exact-action ApprovalRecord using the approver's Ed25519 private key.
func SignApproval(rec domain.ApprovalRecord, approverPriv ed25519.PrivateKey) (domain.ApprovalRecord, error) {
	if len(approverPriv) != ed25519.PrivateKeySize {
		return domain.ApprovalRecord{}, fmt.Errorf("invalid Ed25519 private key size")
	}
	msg := domain.CanonicalApprovalSigningBytes(rec)
	sig := ed25519.Sign(approverPriv, msg)
	rec.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	return rec, nil
}

// VerifyApprovalSignature verifies the Ed25519 signature of an ApprovalRecord against the approver's public key.
func VerifyApprovalSignature(rec domain.ApprovalRecord, approverPubB64 string) bool {
	pub, err := DecodePublicKeyBase64(approverPubB64)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(rec.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := domain.CanonicalApprovalSigningBytes(rec)
	return ed25519.Verify(pub, msg, sig)
}
