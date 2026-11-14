package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestCertificateIntermediatesPoolIsolation(t *testing.T) {
	cert, err := x509.ParseCertificate(testRSA2048Cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []bool{false, true} {
		config := &Config{RootCAs: x509.NewCertPool()}
		if supplied {
			config.CertificateIntermediates = x509.NewCertPool()
		}
		pool := config.certificateIntermediates()
		pool.AddCert(cert)
		if len(config.RootCAs.Subjects()) != 0 {
			t.Fatal("issuer candidate was promoted to a root")
		}
		if len(config.certificateIntermediates().Subjects()) != 0 {
			t.Fatal("verification mutated the configured candidate pool")
		}
		if config.Clone().CertificateIntermediates != config.CertificateIntermediates {
			t.Fatal("Clone did not retain the immutable pool, like RootCAs")
		}
	}
}

func TestCertificateIntermediatesNormalAndECHRejection(t *testing.T) {
	now := time.Now()
	issue := func(serial int64, name string, ca bool, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: ca, BasicConstraintsValid: true, DNSNames: []string{name},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, signer = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	root, rootKey := issue(1, "root", true, nil, nil)
	issuer, issuerKey := issue(2, "issuer", true, root, rootKey)
	leaf, _ := issue(3, "public.example", false, issuer, issuerKey)

	for _, rejected := range []bool{false, true} {
		for _, candidates := range []bool{false, true} {
			for _, trusted := range []bool{false, true} {
				t.Run(fmt.Sprintf("echRejected=%v/candidates=%v/trusted=%v", rejected, candidates, trusted), func(t *testing.T) {
					config := &Config{RootCAs: x509.NewCertPool(), ServerName: "public.example"}
					if trusted {
						config.RootCAs.AddCert(root)
					}
					if candidates {
						config.CertificateIntermediates = x509.NewCertPool()
						config.CertificateIntermediates.AddCert(issuer)
					}
					if rejected {
						config.ServerName = "private.example"
						config.EncryptedClientHelloConfigList = []byte{1}
						// ECH rejection must authenticate the outer name even if the
						// ordinary inner-handshake verification was disabled.
						config.InsecureSkipVerify = true
					}
					conn := &Conn{conn: &discardConn{}, config: config, serverName: "public.example", vers: VersionTLS13}
					err := conn.verifyServerCertificate([][]byte{leaf.Raw})
					if candidates && trusted {
						if err != nil || len(conn.verifiedChains) == 0 || len(conn.verifiedChains[0]) != 3 || len(conn.peerCertificates) != 1 {
							t.Fatalf("chain completion failed: %v", err)
						}
					} else if err == nil {
						t.Fatal("accepted an incomplete or untrusted chain")
					}
				})
			}
		}
	}
}
