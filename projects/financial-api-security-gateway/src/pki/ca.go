package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// TestCA is a local-lab-only X.509 Certificate Authority for mTLS simulation.
type TestCA struct {
	Cert       *x509.Certificate
	PrivateKey *ecdsa.PrivateKey
	CertPEM    []byte
	Pool       *x509.CertPool
	serialSeq  atomic.Int64
	clock      domain.Clock
}

// IssuedCert holds an X.509 certificate, private key, TLS pair, and metadata.
type IssuedCert struct {
	Cert       *x509.Certificate
	PrivateKey *ecdsa.PrivateKey
	CertPEM    []byte
	KeyPEM     []byte
	TLSCert    tls.Certificate
	Info       domain.PeerCertInfo
}

// NewTestCA creates an ephemeral local-lab ECDSA P-256 Root CA.
func NewTestCA(commonName string, clock domain.Clock) (*TestCA, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	now := clock.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"FinSec Lab Test CA"},
			OrganizationalUnit: []string{"LOCAL-LAB-TEST-ONLY"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	ca := &TestCA{
		Cert:       cert,
		PrivateKey: priv,
		CertPEM:    certPEM,
		Pool:       pool,
		clock:      clock,
	}
	ca.serialSeq.Store(100)
	return ca, nil
}

// IssueServerCert issues a TLS server certificate for localhost and 127.0.0.1.
func (ca *TestCA) IssueServerCert(commonName string, ttl time.Duration) (*IssuedCert, error) {
	return ca.issueLeaf(leafSpec{
		commonName: commonName,
		dnsNames:   []string{"localhost", "gateway.finsec.local"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1")},
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore:  ca.clock.Now().Add(-1 * time.Minute),
		notAfter:   ca.clock.Now().Add(ttl),
	})
}

// IssueClientCert issues an mTLS client certificate with CN and SPIFFE URI SAN.
func (ca *TestCA) IssueClientCert(clientID, spiffeID string, ttl time.Duration) (*IssuedCert, error) {
	var uris []*url.URL
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			return nil, fmt.Errorf("invalid spiffe id %q: %w", spiffeID, err)
		}
		uris = append(uris, u)
	}
	now := ca.clock.Now()
	return ca.issueLeaf(leafSpec{
		commonName: clientID,
		uris:       uris,
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore:  now.Add(-1 * time.Minute),
		notAfter:   now.Add(ttl),
	})
}

// IssueExpiredClientCert issues an already-expired client certificate for negative testing.
func (ca *TestCA) IssueExpiredClientCert(clientID, spiffeID string) (*IssuedCert, error) {
	var uris []*url.URL
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			return nil, err
		}
		uris = append(uris, u)
	}
	now := ca.clock.Now()
	return ca.issueLeaf(leafSpec{
		commonName: clientID,
		uris:       uris,
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore:  now.Add(-2 * time.Hour),
		notAfter:   now.Add(-1 * time.Hour),
	})
}

// IssueWrongEKUClientCert issues a cert with ServerAuth EKU only (invalid for client auth).
func (ca *TestCA) IssueWrongEKUClientCert(clientID string) (*IssuedCert, error) {
	now := ca.clock.Now()
	return ca.issueLeaf(leafSpec{
		commonName: clientID,
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore:  now.Add(-1 * time.Minute),
		notAfter:   now.Add(1 * time.Hour),
	})
}

type leafSpec struct {
	commonName string
	dnsNames   []string
	ipAddrs    []net.IP
	uris       []*url.URL
	extUsage   []x509.ExtKeyUsage
	notBefore  time.Time
	notAfter   time.Time
}

func (ca *TestCA) issueLeaf(spec leafSpec) (*IssuedCert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial := big.NewInt(ca.serialSeq.Add(1))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         spec.commonName,
			Organization:       []string{"FinSec Lab"},
			OrganizationalUnit: []string{"LOCAL-LAB-TEST-ONLY"},
		},
		DNSNames:              spec.dnsNames,
		IPAddresses:           spec.ipAddrs,
		URIs:                  spec.uris,
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           spec.extUsage,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("build tls keypair: %w", err)
	}
	return &IssuedCert{
		Cert:       cert,
		PrivateKey: priv,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		TLSCert:    tlsCert,
		Info:       ExtractPeerCertInfo(cert),
	}, nil
}

// CertThumbprintSHA256 computes the RFC 8705 x5t#S256 certificate thumbprint.
func CertThumbprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SerialHex formats an X.509 serial number as lowercase hexadecimal.
func SerialHex(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.SerialNumber.Bytes())
}

// ExtractPeerCertInfo extracts normalized identity fields from an X.509 peer cert.
func ExtractPeerCertInfo(cert *x509.Certificate) domain.PeerCertInfo {
	if cert == nil {
		return domain.PeerCertInfo{}
	}
	spiffe := ""
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			spiffe = u.String()
			break
		}
	}
	return domain.PeerCertInfo{
		Present:          true,
		CommonName:       cert.Subject.CommonName,
		SPIFFEID:         spiffe,
		SerialHex:        SerialHex(cert),
		ThumbprintSHA256: CertThumbprintSHA256(cert),
		IssuerCN:         cert.Issuer.CommonName,
	}
}

// CertRevocationStore tracks revoked certificate serial numbers.
type CertRevocationStore interface {
	Revoke(serialHex string, reason string)
	IsRevoked(serialHex string) bool
	Count() int
}

// MemoryCertRevocationStore is a thread-safe in-memory certificate revocation list.
type MemoryCertRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]string
}

func NewMemoryCertRevocationStore() *MemoryCertRevocationStore {
	return &MemoryCertRevocationStore{revoked: make(map[string]string)}
}

func (s *MemoryCertRevocationStore) Revoke(serialHex string, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serialHex] = reason
}

func (s *MemoryCertRevocationStore) IsRevoked(serialHex string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[serialHex]
	return ok
}

func (s *MemoryCertRevocationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.revoked)
}
