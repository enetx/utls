// SPDX-License-Identifier: BSD-3-Clause
package tls

import (
	"bytes"
	"testing"
)

func TestCustomECHOuterQUICParameters(t *testing.T) {
	for _, mode := range []string{"valid", "empty-public", "wrong-inner", "compressed", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			full := []byte{0x0f, 1, 0xab, 4, 1, 16}
			cfg := innerTestConfig(t)
			cfg.ECHClientHelloInner = func(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
				spec, err := innerTestPolicy(info)
				if err != nil {
					return nil, err
				}
				params := bytes.Clone(info.QUICTransportParameters)
				spec.OuterQUICTransportParameters = []byte{0x0f, 1, 0xab}
				if mode == "empty-public" {
					spec.OuterQUICTransportParameters = []byte{}
				}
				if mode == "wrong-inner" {
					params = nil
				}
				if mode == "compressed" {
					spec.Extensions = append(spec.Extensions, ECHClientHelloExtension{ID: 57, Outer: true})
				} else {
					spec.Extensions = append([]ECHClientHelloExtension{{ID: 57, Data: params}}, spec.Extensions...)
				}
				return spec, nil
			}
			spec := innerTestSpec()
			spec.Extensions = append(spec.Extensions, &QUICTransportParametersExtension{})
			var client *UConn
			if mode == "tcp" {
				client = UClient(nil, cfg, HelloCustom)
				if err := client.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
			} else {
				q := UQUICClient(&QUICConfig{TLSConfig: cfg}, HelloCustom)
				if err := q.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
				q.SetTransportParameters(full)
				client = q.conn
			}
			err := client.BuildHandshakeState()
			valid := mode == "valid" || mode == "empty-public"
			if (err == nil) != valid {
				t.Fatalf("valid=%t error=%v", valid, err)
			}
			if !valid {
				return
			}
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("invalid outer")
			}
			if !bytes.Equal(client.echCtx.innerHello.quicTransportParameters, full) || !bytes.Equal(client.quic.transportParams, full) {
				t.Fatal("inner/engine parameters were changed")
			}
			want := []byte{0x0f, 1, 0xab}
			if mode == "empty-public" {
				want = []byte{}
			}
			if !bytes.Equal(outer.quicTransportParameters, want) {
				t.Fatal("public parameters were not applied")
			}
			inner, err := decodeInnerClientHello(outer, client.echCtx.encodedInner)
			if err != nil || !bytes.Equal(inner.original, client.echCtx.innerHello.original) {
				t.Fatalf("peer transcript: %v", err)
			}
		})
	}
}
