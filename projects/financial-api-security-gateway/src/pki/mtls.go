package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ServerTLSConfig builds a strict TLS 1.3 mTLS server configuration with live revocation checks.
func ServerTLSConfig(ca *TestCA, serverCert *IssuedCert, revocations CertRevocationStore) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert.TLSCert},
		ClientCAs:    ca.Pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return errors.New("no verified client certificate chain")
			}
			leaf := verifiedChains[0][0]
			if revocations != nil && revocations.IsRevoked(SerialHex(leaf)) {
				return fmt.Errorf("client certificate serial %s is revoked", SerialHex(leaf))
			}
			return nil
		},
	}
}

// ClientTLSConfig builds a TLS 1.3 mTLS client configuration trusting the TestCA.
func ClientTLSConfig(ca *TestCA, clientCert *IssuedCert) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    ca.Pool,
		ServerName: "localhost",
	}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{clientCert.TLSCert}
	}
	return cfg
}
