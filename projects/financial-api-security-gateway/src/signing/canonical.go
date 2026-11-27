package signing

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CanonicalRequestString constructs the deterministic v1 signing string and body SHA-256 hex digest.
// Format:
//   v1\nMETHOD\nCANONICAL_PATH\nCANONICAL_QUERY\nTIMESTAMP_RFC3339\nNONCE\nKEY_ID\nSHA256_HEX(BODY)
func CanonicalRequestString(method, path, rawQuery, timestamp, nonce, keyID string, body []byte) (string, string) {
	sum := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(sum[:])
	normMethod := strings.ToUpper(strings.TrimSpace(method))
	normQuery := NormalizeQuery(rawQuery)
	canonical := strings.Join([]string{
		"v1",
		normMethod,
		path,
		normQuery,
		timestamp,
		nonce,
		keyID,
		bodyHex,
	}, "\n")
	return canonical, bodyHex
}

// NormalizeQuery sorts query parameters lexicographically by key and value for deterministic signing.
func NormalizeQuery(rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return ""
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := append([]string(nil), vals[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// SignEd25519 signs the canonical request string with an Ed25519 private key and returns base64url without padding.
func SignEd25519(priv ed25519.PrivateKey, canonical string) string {
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyEd25519 verifies a base64url Ed25519 signature over the canonical request string.
func VerifyEd25519(pub ed25519.PublicKey, canonical, sigB64 string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(canonical), sig)
}

// SignHMACSHA256 signs the canonical request string with HMAC-SHA256 and returns base64url without padding.
func SignHMACSHA256(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyHMACSHA256 verifies a base64url HMAC-SHA256 signature in constant time.
func VerifyHMACSHA256(secret []byte, canonical, sigB64 string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig)
}

// SignRequest is a convenience helper for clients constructing signed request headers.
func SignRequest(alg, keyID, timestamp, nonce, method, path, rawQuery string, body []byte, edPriv ed25519.PrivateKey, hmacSecret []byte) (string, error) {
	canonical, _ := CanonicalRequestString(method, path, rawQuery, timestamp, nonce, keyID, body)
	switch alg {
	case "Ed25519":
		if len(edPriv) != ed25519.PrivateKeySize {
			return "", fmt.Errorf("invalid Ed25519 private key size")
		}
		return SignEd25519(edPriv, canonical), nil
	case "HMAC-SHA256":
		if len(hmacSecret) == 0 {
			return "", fmt.Errorf("empty HMAC secret")
		}
		return SignHMACSHA256(hmacSecret, canonical), nil
	default:
		return "", fmt.Errorf("unsupported request signing algorithm %q", alg)
	}
}
