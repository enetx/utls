package tls

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func assertECHInnerKeyLog(t *testing.T, client *UConn, data []byte, count int) {
	t.Helper()
	var records [][]byte
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "UTLS_ECH_INNER_CLIENT_HELLO" {
			continue
		}
		if len(fields) != 3 {
			t.Fatal("malformed ECH key-log record")
		}
		random, err := hex.DecodeString(fields[1])
		if err != nil || !bytes.Equal(random, client.HandshakeState.Hello.Random) {
			t.Fatal("ECH key-log record does not identify the outer ClientHello")
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) < 4 || raw[0] != typeClientHello {
			t.Fatal("invalid ECH key-log handshake message")
		}
		records = append(records, raw)
	}
	if len(records) != count {
		t.Fatalf("ECH key-log records: got %d, want %d", len(records), count)
	}
	if !bytes.Equal(records[len(records)-1], client.echCtx.innerHello.original) {
		t.Fatal("ECH key-log record differs from the bound private ClientHello")
	}
}

type echKeyLogErrorWriter struct{ err error }

func (w echKeyLogErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestECHInnerKeyLogErrorPreventsClientHello(t *testing.T) {
	config, _ := innerTestConfigPair(t)
	want := errors.New("capture writer failed")
	config.KeyLogWriter = echKeyLogErrorWriter{want}
	a, b := localPipe(t)
	defer a.Close()
	defer b.Close()
	read := make(chan int, 1)
	go func() {
		var first [1]byte
		n, _ := io.ReadFull(a, first[:])
		read <- n
		a.Close()
	}()
	client := UClient(b, config, HelloCustom)
	if err := client.ApplyPreset(innerTestSpec()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err := client.HandshakeContext(ctx)
	b.Close()
	if !errors.Is(err, want) {
		t.Fatalf("lost key-log writer error: %v", err)
	}
	if n := <-read; n != 0 {
		t.Fatal("ClientHello was sent after the capture writer failed")
	}
}

type earlyKeyLogWriter struct {
	bytes.Buffer
	err error
}

func (w *earlyKeyLogWriter) Write(p []byte) (int, error) {
	if w.err != nil && bytes.HasPrefix(p, []byte("CLIENT_EARLY_TRAFFIC_SECRET ")) {
		return 0, w.err
	}
	return w.Buffer.Write(p)
}

func TestQUICEarlyTrafficKeyLog(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			cc := testConfigClient.Clone()
			cc.MinVersion, cc.NextProtos = VersionTLS13, []string{"h3"}
			cc.ClientSessionCache = NewLRUClientSessionCache(1)
			sc := testConfigServer.Clone()
			sc.MinVersion, sc.NextProtos = VersionTLS13, []string{"h3"}
			var log earlyKeyLogWriter
			cc.KeyLogWriter = &log
			for attempt := 0; attempt < 2; attempt++ {
				cli := newTestQUICClient(t, &QUICConfig{TLSConfig: cc})
				srv := newTestQUICServer(t, &QUICConfig{TLSConfig: sc})
				cli.conn.SetTransportParameters(nil)
				srv.conn.SetTransportParameters(nil)
				srv.ticketOpts.EarlyData = true
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				err := runTestQUICConnection(ctx, cli, srv, nil)
				cancel()
				if attempt == 1 && fail {
					if !errors.Is(err, log.err) {
						t.Fatalf("early key-log error lost: %v", err)
					}
					if cli.writeSecret[QUICEncryptionLevelEarly].secret != nil {
						t.Fatal("activated early key after log failure")
					}
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for line := range strings.SplitSeq(log.String(), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 || fields[0] != "CLIENT_EARLY_TRAFFIC_SECRET" {
						continue
					}
					if len(fields) != 3 || len(fields[1]) != 64 {
						t.Fatal("bad early key-log framing")
					}
					secret, err := hex.DecodeString(fields[2])
					if err != nil || !bytes.Equal(secret, cli.writeSecret[QUICEncryptionLevelEarly].secret) {
						t.Fatal("early key log changed the actual secret")
					}
					count++
				}
				if count != attempt {
					t.Fatalf("early records=%d, want %d", count, attempt)
				}
				log.Reset()
				if fail {
					log.err = errors.New("early key-log writer failed")
				}
			}
		})
	}
}
