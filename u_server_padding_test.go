package tls

import (
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestServerPaddingValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		offer     []byte
		response  []byte
		wantError bool
	}{
		{"zero", []byte{0, 0}, []byte{}, false},
		{"opaque-bytes", []byte{0, 3}, []byte{1, 2, 3}, false},
		{"maximum", []byte{0x40, 0}, make([]byte, 16384), false},
		{"wrong-length", []byte{0, 0}, []byte{0}, true},
		{"missing-request", nil, []byte{}, true},
		{"malformed-request", []byte{0}, []byte{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var extensions []TLSExtension
			if tc.offer != nil {
				extensions = append(extensions, &GenericExtension{Id: extensionServerPadding, Data: tc.offer})
			}
			raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil, []uint16{TLS_AES_128_GCM_SHA256}, []byte{0}, extensions)
			if err != nil {
				t.Fatal(err)
			}
			hello := new(clientHelloMsg)
			if !hello.unmarshal(raw) {
				t.Fatal("invalid hello")
			}
			builder := cryptobyte.NewBuilder(nil)
			builder.AddUint8(typeEncryptedExtensions)
			builder.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(extensionServerPadding)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tc.response) })
				})
			})
			message := new(encryptedExtensionsMsg)
			if !message.unmarshal(builder.BytesOrPanic()) || !message.utls.serverPaddingPresent || message.utls.serverPaddingLength != len(tc.response) {
				t.Fatal("lost server padding presence or length")
			}
			a, b := localPipe(t)
			b.Close()
			defer a.Close()
			hs := &clientHandshakeStateTLS13{c: Client(a, &Config{}), hello: hello}
			if err := hs.readServerPadding(message); (err != nil) != tc.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, tc.wantError)
			}
			if err := hs.readServerPadding(new(encryptedExtensionsMsg)); err != nil {
				t.Fatal("server may omit padding", err)
			}
		})
	}
}
