package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	creflect "github.com/xtls/xray-core/common/reflect"
)

// This is the actual pinned CLI response encoder, without a Core instance,
// command, listener or stats manager. In particular, a present zero counter
// omits value; a missing direction omits the entire counter record.
func TestCLIStatsWire(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("counter corpus source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "traffic-counters.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string               `json:"name"`
		Counters []*statscommand.Stat `json:"counters"`
		Wire     json.RawMessage      `json:"wire"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 11 {
		t.Fatalf("expected 11 counter wire cases, got %d", len(cases))
	}
	decode := func(t *testing.T, data []byte) any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber() // Keep signed 64-bit maxima exact.
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			encoded, ok := creflect.MarshalToJson(&statscommand.QueryStatsResponse{Stat: tc.Counters}, true)
			if !ok {
				t.Fatal("pinned CLI response encoder refused the fixture")
			}
			if !reflect.DeepEqual(decode(t, []byte(encoded)), decode(t, tc.Wire)) {
				t.Fatal("counter corpus differs from the actual pinned CLI wire format")
			}
		})
	}
}
