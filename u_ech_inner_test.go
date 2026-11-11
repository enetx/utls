package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func innerTestConfig(t *testing.T) *Config {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint16(0x20)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) { list.AddBytes(b.BytesOrPanic()) })
	return &Config{ServerName: "secret.example", MinVersion: VersionTLS13, NextProtos: []string{"h2"}, EncryptedClientHelloConfigList: list.BytesOrPanic()}
}

func innerTestSpec() *ClientHelloSpec {
	return &ClientHelloSpec{CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, Extensions: []TLSExtension{
		&SNIExtension{}, &SupportedCurvesExtension{Curves: []CurveID{X25519}},
		&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}}, &ALPNExtension{AlpnProtocols: []string{"h2"}},
		&GenericExtension{Id: 0x1234, Data: []byte{1, 2, 3}}, &GREASEEncryptedClientHelloExtension{},
	}}
}

func innerTestPolicy(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
	sni := &SNIExtension{ServerName: info.ServerName}
	data := make([]byte, sni.Len())
	_, err := sni.Read(data)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &ECHClientHelloSpec{CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, Extensions: []ECHClientHelloExtension{
		{ID: 0, Data: data[4:]}, {ID: 0xfe0d, Data: []byte{1}}, {ID: 43, Data: []byte{2, 3, 4}},
		{ID: 10, Outer: true}, {ID: 51, Outer: true}, {ID: 13, Outer: true}, {ID: 16, Outer: true}, {ID: 0x1234, Outer: true},
	}}, nil
}

func innerTestClient(t *testing.T, cfg *Config) *UConn {
	t.Helper()
	client := UClient(nil, cfg, HelloCustom)
	if err := client.ApplyPreset(innerTestSpec()); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCustomECHInnerRoundTrip(t *testing.T) {
	cfg := innerTestConfig(t)
	calls := 0
	cfg.ECHClientHelloInner = func(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
		calls++
		spec, err := innerTestPolicy(info)
		info.ClientHello[0] = 255 // callback input does not alias the live outer hello
		info.NextProtos[0] = "changed"
		return spec, err
	}
	clone := cfg.Clone()
	client := innerTestClient(t, clone)
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || cfg.NextProtos[0] != "h2" {
		t.Fatal("callback/clone ownership changed")
	}
	outer := new(clientHelloMsg)
	if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
		t.Fatal("invalid outer")
	}
	decoded, err := decodeInnerClientHello(outer, client.echCtx.encodedInner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.original, client.echCtx.innerHello.original) {
		t.Fatal("client and server transcripts disagree")
	}
	exts, err := extractRawExtensions(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(exts) != 8 || exts[7].extType != 0x1234 || !bytes.Equal(exts[7].data, []byte{1, 2, 3}) {
		t.Fatalf("lost opaque extension: %v", exts)
	}
	if decoded.serverName != "secret.example" || outer.serverName != "public.example" {
		t.Fatal("inner and outer names were mixed")
	}
	// A nil callback retains the unmodified upstream construction path.
	stock := innerTestClient(t, innerTestConfig(t))
	if err := stock.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if stock.echCtx.customInner {
		t.Fatal("nil callback changed upstream behavior")
	}
}

func TestCustomECHInnerValidation(t *testing.T) {
	sentinel := errors.New("policy failed")
	tests := map[string]func(*ECHClientHelloSpec){
		"duplicate":         func(s *ECHClientHelloSpec) { s.Extensions = append(s.Extensions, s.Extensions[0]) },
		"absent-reference":  func(s *ECHClientHelloSpec) { s.Extensions[7].ID = 0x1235 },
		"noncontiguous":     func(s *ECHClientHelloSpec) { s.Extensions[4].Outer = false },
		"reference-order":   func(s *ECHClientHelloSpec) { s.Extensions[4], s.Extensions[5] = s.Extensions[5], s.Extensions[4] },
		"outer-marker":      func(s *ECHClientHelloSpec) { s.Extensions[1].Outer = true; s.Extensions[1].Data = nil },
		"wrong-marker":      func(s *ECHClientHelloSpec) { s.Extensions[1].Data = []byte{0} },
		"wrong-name":        func(s *ECHClientHelloSpec) { s.Extensions[0].Data[5] = 'x' },
		"legacy-cipher":     func(s *ECHClientHelloSpec) { s.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} },
		"grease-only":       func(s *ECHClientHelloSpec) { s.CipherSuites = []uint16{0x0a0a} },
		"empty-cipher":      func(s *ECHClientHelloSpec) { s.CipherSuites = nil },
		"legacy-version":    func(s *ECHClientHelloSpec) { s.Extensions[2].Data = []byte{2, 3, 3} },
		"missing-marker":    func(s *ECHClientHelloSpec) { s.Extensions = append(s.Extensions[:1], s.Extensions[2:]...) },
		"changed-key-share": func(s *ECHClientHelloSpec) { s.Extensions[4] = ECHClientHelloExtension{ID: 51, Data: []byte{0, 0}} },
		"PSK": func(s *ECHClientHelloSpec) {
			s.Extensions = append(s.Extensions, ECHClientHelloExtension{ID: 41, Data: []byte{0, 0}})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := innerTestConfig(t)
			cfg.ECHClientHelloInner = func(i ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
				s, e := innerTestPolicy(i)
				if e == nil {
					mutate(s)
				}
				return s, e
			}
			client := innerTestClient(t, cfg)
			if err := client.BuildHandshakeState(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	t.Run("callback-error", func(t *testing.T) {
		cfg := innerTestConfig(t)
		cfg.ECHClientHelloInner = func(ECHClientHelloInfo) (*ECHClientHelloSpec, error) { return nil, sentinel }
		if err := innerTestClient(t, cfg).BuildHandshakeState(); !errors.Is(err, sentinel) {
			t.Fatalf("lost cause: %v", err)
		}
	})
	t.Run("nil-result", func(t *testing.T) {
		cfg := innerTestConfig(t)
		cfg.ECHClientHelloInner = func(ECHClientHelloInfo) (*ECHClientHelloSpec, error) { return nil, nil }
		if err := innerTestClient(t, cfg).BuildHandshakeState(); err == nil {
			t.Fatal("nil policy result accepted")
		}
	})
}

func FuzzCustomECHInnerRaw(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = encodeInnerClientHelloFromRaw(&clientHelloMsg{original: raw, serverName: "secret.example"}, nil, 32)
	})
}

func TestCustomECHInnerQUICStartError(t *testing.T) {
	cfg := innerTestConfig(t)
	sentinel := errors.New("inner policy failed")
	cfg.ECHClientHelloInner = func(ECHClientHelloInfo) (*ECHClientHelloSpec, error) { return nil, sentinel }
	q := UQUICClient(&QUICConfig{TLSConfig: cfg}, HelloCustom)
	if err := q.ApplyPreset(innerTestSpec()); err != nil {
		t.Fatal(err)
	}
	q.SetTransportParameters([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Start(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatalf("lost callback error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("QUIC Start blocked after ClientHello construction failed")
	}
	if err := q.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close lost handshake error: %v", err)
	}
}
