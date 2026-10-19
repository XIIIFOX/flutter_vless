package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf/serial"
)

// File-only comparison with the existing native localhost adaptation. Unlike
// prepare, this expects that adaptation to change the server address and tag.
// No Core instance, resolver, listener or network setting is used.
func prepareLocalhostDNSTag(t *testing.T, data []byte, reject bool) map[string]any {
	t.Helper()
	directory := t.TempDir()
	input, output := filepath.Join(directory, "source.json"), filepath.Join(directory, "effective.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("NATIVE_DNS_PREPARER"), "--prepare-dns-fixture",
		input, output, loopbackInterface(t), "endpoint.invalid", "127.0.0.1")
	combined, err := command.CombinedOutput()
	retained, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(retained, data) {
		t.Fatal("native preparation changed the caller source file", readErr)
	}
	if reject {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || ctx.Err() != nil {
			t.Fatalf("invalid DNS tag was not explicitly rejected: %v: %s", err, combined)
		}
		if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
			t.Fatal("rejected DNS preparation published an effective profile", statErr)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("valid localhost DNS tag rejected: %v: %s", err, combined)
	}
	prepared, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoded.Build(); err != nil {
		t.Fatal("localhost DNS adaptation broke valid Core configuration", err)
	}
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	return effective
}

func testLocalhostDNSTags(t *testing.T, native bool) {
	t.Helper()
	cases := preparationCorpus(t, "dns-default-tags.json", 3)
	var baseline map[string]any
	for _, tc := range cases {
		t.Run("dns_tag_"+tc.Name, func(t *testing.T) {
			data, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatal("source DNS tag rejected by pinned Core", err)
			}
			if _, err := decoded.Build(); err != nil {
				t.Fatal("source DNS tag cannot build with pinned Core", err)
			}
			if !native {
				return
			}
			effective := prepareLocalhostDNSTag(t, data, false)
			dns := effective["dns"].(map[string]any)
			server := dns["servers"].([]any)[0].(map[string]any)
			tag, ok := server["tag"].(string)
			if !ok || tag == "" || server["address"] != "tcp://1.1.1.1" {
				t.Fatal("localhost DNS did not use the protected numeric TCP adaptation")
			}
			var expected map[string]any
			if err := json.Unmarshal(data, &expected); err != nil {
				t.Fatal(err)
			}
			wantDNS := expected["dns"].(map[string]any)
			wantServer := wantDNS["servers"].([]any)[0].(map[string]any)
			wantServer["address"], wantServer["tag"] = "tcp://1.1.1.1", tag
			if !reflect.DeepEqual(dns, wantDNS) {
				t.Fatal("localhost adaptation changed other caller DNS fields")
			}
			if baseline == nil {
				baseline = effective
			} else if !reflect.DeepEqual(baseline, effective) {
				t.Fatal("null or empty DNS tag differs from the absent-tag effective configuration")
			}
		})
	}
	for _, invalid := range []struct {
		name  string
		value any
	}{{"bool", false}, {"number", float64(7)}, {"array", []any{}}, {"object", map[string]any{}}} {
		t.Run("dns_tag_invalid_"+invalid.name, func(t *testing.T) {
			data, err := json.Marshal(cases[0].Config)
			if err != nil {
				t.Fatal(err)
			}
			var source map[string]any
			if err := json.Unmarshal(data, &source); err != nil {
				t.Fatal(err)
			}
			server := source["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			server["tag"] = invalid.value
			data, err = json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := serial.DecodeJSONConfig(bytes.NewReader(data)); err == nil {
				t.Fatal("invalid DNS tag unexpectedly accepted by pinned Core")
			}
			if native {
				prepareLocalhostDNSTag(t, data, true)
			}
		})
	}
}
