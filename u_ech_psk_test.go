package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestCustomECHSessionResumption(t *testing.T) {
	for _, mode := range []ECHOuterPSKMode{ECHOuterPSKOmit, ECHOuterPSKRandomized} {
		for _, hrr := range []bool{false, true} {
			for _, cipher := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384} {
				t.Run(fmt.Sprintf("mode-%d/hrr-%t/%s", mode, hrr, CipherSuiteName(cipher)), func(t *testing.T) {
					testCustomECHSessionResumption(t, mode, hrr, cipher)
				})
			}
		}
	}
}

func TestECHOuterPSKCannotResume(t *testing.T) {
	a, b := localPipe(t)
	b.Close()
	defer a.Close()
	conn := Client(a, &Config{})
	hello := &clientHelloMsg{keyShares: []keyShare{{group: X25519}}}
	hs := &clientHandshakeStateTLS13{
		c: conn, hello: hello,
		echContext:  &echClientContext{customInner: true, innerHello: new(clientHelloMsg)},
		serverHello: &serverHelloMsg{serverShare: keyShare{group: X25519}, selectedIdentityPresent: true},
	}
	if err := hs.processServerHello(); err == nil || err.Error() != "tls: server selected an outer ECH PSK placeholder" {
		t.Fatalf("outer resumption accepted: %v", err)
	}
}

func TestRandomizedECHPSK(t *testing.T) {
	identities := []PskIdentity{{Label: []byte("private-ticket"), ObfuscatedTicketAge: 42}}
	binders := [][]byte{bytes.Repeat([]byte{1}, 32)}
	raw := make([]byte, pskExtLen(identities, binders))
	_, err := readPskIntoBytes(raw, identities, binders)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	data := bytes.Clone(raw[4:])
	randomized, err := randomizedECHPSK(data, bytes.NewReader(bytes.Repeat([]byte{2}, 1024)))
	if err != nil || len(randomized) != len(data) || bytes.Equal(randomized, data) || !bytes.Equal(data, raw[4:]) {
		t.Fatalf("invalid randomized PSK: %v", err)
	}
	for _, invalid := range [][]byte{{}, {0, 1, 0}, {0, 0, 0, 2, 2, 0}} {
		if _, err := randomizedECHPSK(invalid, bytes.NewReader(nil)); err == nil {
			t.Fatal("accepted malformed PSK")
		}
	}
	if _, err := randomizedECHPSK(data, bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("lost entropy error: %v", err)
	}
}

func FuzzRandomizedECHPSK(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = randomizedECHPSK(raw, bytes.NewReader(make([]byte, len(raw)))) })
}

func testCustomECHSessionResumption(t *testing.T, mode ECHOuterPSKMode, hrr bool, cipher uint16) {
	clientConfig, key := innerTestConfigPair(t)
	clientConfig.ServerName = testConfigClient.ServerName
	clientConfig.RootCAs = testRootCertPool
	clientConfig.Time = testTime
	clientConfig.OmitEmptyPsk = true
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(4)
	clientConfig.ECHClientHelloInner = func(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
		spec, err := innerTestPolicy(info)
		if err != nil {
			return nil, err
		}
		spec.OuterPSK = mode
		spec.CipherSuites = []uint16{cipher}
		spec.Extensions = append(spec.Extensions, ECHClientHelloExtension{ID: 45, Outer: true})
		return spec, nil
	}
	serverConfig := testConfigServer.Clone()
	serverConfig.MinVersion = VersionTLS13
	serverConfig.NextProtos = []string{"h2"}
	serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{key}
	serverConfig.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
	for attempt := range 2 {
		var keyLog bytes.Buffer
		clientConfig.KeyLogWriter = &keyLog

		if hrr && attempt > 0 {
			serverConfig.CurvePreferences = []CurveID{CurveP384}
		}
		a, b := localPipe(t)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		server := Server(a, serverConfig)
		done := make(chan error, 1)
		go func() {
			defer a.Close()
			if err := server.HandshakeContext(ctx); err != nil {
				done <- err
				return
			}
			_, err := server.Write([]byte{'x'})
			done <- err
		}()
		client := UClient(b, clientConfig.Clone(), HelloCustom)
		spec := innerTestSpec()
		spec.CipherSuites = []uint16{cipher}
		spec.Extensions[1].(*SupportedCurvesExtension).Curves = []CurveID{X25519, CurveP384}
		spec.Extensions = append(spec.Extensions, &PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}}, &UtlsPreSharedKeyExtension{})
		if err := client.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
		if err := client.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		if keyLog.Len() != 0 {
			t.Fatal("building an unsent ClientHello wrote a key-log record")
		}
		err := client.HandshakeContext(ctx)
		if err == nil {
			var payload [1]byte
			_, err = io.ReadFull(client, payload[:])
		}
		b.Close()
		cancel()
		serverErr := <-done
		if err != nil {
			t.Fatalf("attempt %d: %v (server: %v)", attempt, err, serverErr)
		}
		if serverErr != nil {
			t.Fatal(serverErr)
		}
		state := client.ConnectionState()
		if !state.ECHAccepted || state.DidResume != (attempt > 0) || len(state.VerifiedChains) == 0 {
			t.Fatalf("attempt %d: invalid resumption/ECH state: %+v", attempt, state)
		}
		keyLogCount := 1
		if hrr && attempt > 0 {
			keyLogCount++
		}
		assertECHInnerKeyLog(t, client, keyLog.Bytes(), keyLogCount)
		if len(client.echCtx.innerHello.pskIdentities) > 0 {
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("malformed outer")
			}
			inner := client.echCtx.innerHello
			if bytes.Contains(outer.original, inner.pskIdentities[0].label) {
				t.Fatal("real PSK identity exposed in outer")
			}
			if mode == ECHOuterPSKOmit && len(outer.pskIdentities) > 0 {
				t.Fatal("unexpected outer PSK")
			}
			if mode == ECHOuterPSKRandomized && (len(outer.pskIdentities) != 1 || len(outer.pskBinders) != 1 ||
				len(outer.pskIdentities[0].label) != len(inner.pskIdentities[0].label) ||
				len(outer.pskBinders[0]) != len(inner.pskBinders[0]) ||
				bytes.Equal(outer.pskBinders[0], inner.pskBinders[0])) {
				t.Fatal("invalid outer PSK camouflage")
			}
		}
	}
}
