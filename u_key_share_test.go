package tls

import (
	"context"
	"testing"
	"time"
)

// NSS retains each generated key and looks it up by the selected group.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13con.c#L3847
func TestMultipleClientKeyShareSelection(t *testing.T) {
	for _, group := range []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384} {
		t.Run(group.String(), func(t *testing.T) {
			a, b := localPipe(t)
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cfg := testConfigServer.Clone()
			cfg.MinVersion = VersionTLS13
			cfg.CurvePreferences = []CurveID{group}
			server := Server(a, cfg)
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(ctx) }()
			client := UClient(b, testConfigClient.Clone(), HelloFirefox_148)
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			state := client.ConnectionState()
			if state.CurveID != group || state.HelloRetryRequest != (group == CurveP384) || len(state.VerifiedChains) == 0 {
				t.Fatalf("wrong key selection/verification: %+v", state)
			}
		})
	}
}
