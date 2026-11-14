// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// TestTLS13ServerCertificateTranscript verifies that CertificateVerify authenticates
// the received certificate bytes, including extension ordering and compression.
func TestTLS13ServerCertificateTranscript(t *testing.T) {
	cert, key, roots := certificateTranscriptIdentity(t)
	ocsp := []byte{0, 5, 0, 5, 1, 0, 0, 1, 1}
	sct := []byte{0, 18, 0, 5, 0, 3, 0, 1, 2}
	unknown := []byte{0xff, 0xa5, 0, 1, 3}
	// A CertificateRequest offering ecdsa_secp256r1_sha256.
	request := []byte{13, 0, 0, 11, 0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3}
	cases := []struct {
		name       string
		extensions []byte
		request    []byte
		compressed bool
		plainConn  bool
	}{
		{name: "OCSP before SCT", extensions: slices.Concat(ocsp, sct)},
		{name: "SCT before OCSP", extensions: slices.Concat(sct, ocsp)},
		{name: "SCT before OCSP with ordinary Conn", extensions: slices.Concat(sct, ocsp), plainConn: true},
		{name: "ignored extension", extensions: slices.Concat(ocsp, unknown, sct)},
		{name: "certificate request", extensions: slices.Concat(sct, ocsp), request: request},
		{name: "compressed certificate", extensions: slices.Concat(sct, ocsp), compressed: true},
		{name: "certificate request and compression", extensions: slices.Concat(sct, ocsp), request: request, compressed: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			certificate := certificateTranscriptMessage(t, cert, tt.extensions)
			if tt.compressed {
				certificate = compressTranscriptCertificate(t, certificate)
			}
			serverMessages := slices.Concat(tt.request, certificate)
			verify := certificateTranscriptSignature(t, key, serverMessages)
			hs := certificateTranscriptState(roots, slices.Concat(serverMessages, verify))
			if tt.plainConn {
				hs.uconn = nil
			}
			if err := hs.readServerCertificate(); err != nil {
				t.Fatalf("readServerCertificate: %v", err)
			}

			want := sha256.Sum256(slices.Concat([]byte("prior handshake transcript"), serverMessages, verify))
			if !bytes.Equal(hs.transcript.Sum(nil), want[:]) {
				t.Errorf("transcript = %x, want %x", hs.transcript.Sum(nil), want)
			}
			if hs.c.peerSigAlg != ECDSAWithP256AndSHA256 {
				t.Errorf("peer signature algorithm = %x, want %x", hs.c.peerSigAlg, ECDSAWithP256AndSHA256)
			}
			if !bytes.Equal(hs.c.ocspResponse, []byte{1}) {
				t.Errorf("OCSP response = %x, want 01", hs.c.ocspResponse)
			}
			if len(hs.c.scts) != 1 || !bytes.Equal(hs.c.scts[0], []byte{2}) {
				t.Errorf("SCTs = %x, want [02]", hs.c.scts)
			}
			if (hs.certReq != nil) != (len(tt.request) != 0) {
				t.Errorf("certificate request present = %v, want %v", hs.certReq != nil, len(tt.request) != 0)
			}
			if hs.c.hand.Len() != 0 {
				t.Errorf("unconsumed handshake bytes = %d, want 0", hs.c.hand.Len())
			}
		})
	}
}

// TestTLS13ServerCertificateTranscriptRejectsInvalidSignature ensures preserving
// the wire transcript does not bypass the server's proof of private-key possession.
func TestTLS13ServerCertificateTranscriptRejectsInvalidSignature(t *testing.T) {
	cert, key, roots := certificateTranscriptIdentity(t)
	certificate := certificateTranscriptMessage(t, cert, nil)
	verify := certificateTranscriptSignature(t, key, certificate)
	verify[len(verify)-1] ^= 1
	hs := certificateTranscriptState(roots, slices.Concat(certificate, verify))
	err := hs.readServerCertificate()
	if err == nil || !strings.Contains(err.Error(), "ECDSA verification failure") {
		t.Fatalf("readServerCertificate error = %v, want ECDSA verification failure", err)
	}
	if hs.c.peerSigAlg != 0 {
		t.Errorf("peer signature algorithm = %x after rejected signature, want 0", hs.c.peerSigAlg)
	}
}

func certificateTranscriptIdentity(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"transcript.example"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2000000000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return der, key, roots
}

func certificateTranscriptMessage(t *testing.T, certificate, extensions []byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(11) // Certificate
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(certificate) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(extensions) })
		})
	})
	wire, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func compressTranscriptCertificate(t *testing.T, certificate []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(certificate[4:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint8(25) // CompressedCertificate
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(1) // zlib
		b.AddUint24(uint32(len(certificate) - 4))
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compressed.Bytes()) })
	})
	wire, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func certificateTranscriptSignature(t *testing.T, key *ecdsa.PrivateKey, serverMessages []byte) []byte {
	t.Helper()
	transcript := sha256.Sum256(slices.Concat([]byte("prior handshake transcript"), serverMessages))
	// Construct RFC 8446 section 4.4.3's signed content independently of signedMessage.
	message := slices.Concat(bytes.Repeat([]byte{0x20}, 64),
		[]byte("TLS 1.3, server CertificateVerify\x00"), transcript[:])
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint8(15) // CertificateVerify
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0403) // ecdsa_secp256r1_sha256
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(signature) })
	})
	wire, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func certificateTranscriptState(roots *x509.CertPool, serverMessages []byte) *clientHandshakeStateTLS13 {
	c := &Conn{
		config: &Config{
			RootCAs:    roots,
			ServerName: "transcript.example",
			Time:       func() time.Time { return time.Unix(1700000000, 0) },
		},
		isClient:  true,
		vers:      VersionTLS13,
		haveVers:  true,
		buffering: true, // Buffer failure alerts too, so the test never needs a network connection.
	}
	c.hand.Write(serverMessages)
	uconn := &UConn{
		Conn:                c,
		Extensions:          []TLSExtension{&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}}},
		certCompressionAlgs: []CertCompressionAlgo{CertCompressionZlib},
	}
	hs := &clientHandshakeStateTLS13{c: c, uconn: uconn, transcript: sha256.New()}
	hs.transcript.Write([]byte("prior handshake transcript"))
	return hs
}
