// SPDX-License-Identifier: BSD-3-Clause
package tls

import (
	"errors"
	"io"
	"testing"
)

func TestEarlyDataTemplateDoesNotReuseEligibility(t *testing.T) {
	early := &EarlyDataExtension{enabled: true}
	spec := innerTestSpec()
	spec.Extensions = append(spec.Extensions, early)
	client := UClient(nil, &Config{ServerName: "example.com"}, HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if !early.enabled {
		t.Fatal("ApplyPreset mutated caller template")
	}
	cloned := client.Extensions[len(client.Extensions)-1].(*EarlyDataExtension)
	if cloned.Len() != 0 {
		t.Fatal("new connection inherited early-data eligibility")
	}
	if n, err := cloned.Read(nil); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty extension did not end its reader: %d %v", n, err)
	}
	client.setEarlyDataExtension(true)
	data, err := io.ReadAll(cloned)
	if err != nil || len(data) != 4 || data[0] != 0 || data[1] != 42 || data[2] != 0 || data[3] != 0 {
		t.Fatalf("early_data encoding: %x %v", data, err)
	}
}
