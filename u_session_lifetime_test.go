package tls

import "testing"

func TestClientSessionUseBy(t *testing.T) {
	for _, state := range []*ClientSessionState{nil, {}, {session: &SessionState{version: VersionTLS12, useBy: 123}}} {
		if state.UseBy() != 0 {
			t.Fatal("non-TLS-1.3 state reported a lifetime")
		}
	}
	state := MakeClientSessionState(nil, VersionTLS13, TLS_AES_128_GCM_SHA256, nil, nil, nil)
	state.SetUseBy(1795000000)
	if state.UseBy() != 1795000000 {
		t.Fatal("ticket expiration getter changed the stored timestamp")
	}
}
