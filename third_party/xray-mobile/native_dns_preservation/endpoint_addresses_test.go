package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

type endpointAddressCase struct {
	Name              string            `json:"name"`
	Environment       map[string]string `json:"environment"`
	ResolvedAddresses map[string]string `json:"resolvedAddresses"`
	Config            map[string]any    `json:"config"`
}

func endpointAddressCorpus(t *testing.T) []endpointAddressCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("corpus source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "endpoint-addresses.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []endpointAddressCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) != 3 {
		t.Fatal("three endpoint Address cases required", err)
	}
	return cases
}

func endpointLiteralControl(t *testing.T, tc endpointAddressCase) []byte {
	t.Helper()
	data, err := json.Marshal(tc.Config)
	if err != nil {
		t.Fatal(err)
	}
	var control map[string]any
	if err := json.Unmarshal(data, &control); err != nil {
		t.Fatal(err)
	}
	for path, value := range tc.ResolvedAddresses {
		parts := strings.Split(path, ".")
		var target any = control
		for _, part := range parts[:len(parts)-1] {
			switch node := target.(type) {
			case map[string]any:
				target = node[part]
			case []any:
				index, err := strconv.Atoi(part)
				if err != nil || index < 0 || index >= len(node) {
					t.Fatal("invalid fixture address path", path)
				}
				target = node[index]
			default:
				t.Fatal("invalid fixture address path", path)
			}
		}
		target.(map[string]any)[parts[len(parts)-1]] = value
	}
	data, err = json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func buildEndpointAddress(t *testing.T, data []byte) proto.Message {
	t.Helper()
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal("endpoint source rejected by pinned Core", err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal("endpoint source cannot build with pinned Core", err)
	}
	return built
}

// Run only a file-only native exporter. Compare its whole effective profile
// with the literal control, including private socket policy and caller data.
func prepareEndpointAddress(t *testing.T, data []byte) map[string]any {
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
		t.Fatal("native preparation changed the endpoint source file", readErr)
	}
	if err != nil {
		t.Fatalf("valid endpoint Address rejected: %v: %s", err, combined)
	}
	prepared, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	buildEndpointAddress(t, prepared)
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	return effective
}

// Core's typed Address decoder is the oracle for one-pass env semantics.
// This creates no Core instance, resolver, listener or network engine.
func testEndpointAddresses(t *testing.T, native bool) {
	for _, tc := range endpointAddressCorpus(t) {
		t.Run("endpoint_"+tc.Name, func(t *testing.T) {
			for _, name := range []string{"FLUTTER_VLESS_FIXTURE_ENDPOINT", "flutter.vless.fixture.endpoint", " flutter.vless.fixture.endpoint "} {
				old, found := os.LookupEnv(name)
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if found {
						_ = os.Setenv(name, old)
					} else {
						_ = os.Unsetenv(name)
					}
				})
			}
			for name, value := range tc.Environment {
				t.Setenv(name, value)
			}
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			control := endpointLiteralControl(t, tc)
			if !proto.Equal(buildEndpointAddress(t, source), buildEndpointAddress(t, control)) {
				t.Fatal("environment Address differs from literal under pinned Core")
			}
			if native {
				baseline := prepareEndpointAddress(t, control)
				t.Log("ENDPOINT_LITERAL_CONTROL_PASS")
				effective := prepareEndpointAddress(t, source)
				if !reflect.DeepEqual(baseline, effective) {
					t.Fatal("endpoint binding changed the effective literal profile")
				}
				if !reflect.DeepEqual(tc.Config["dns"], effective["dns"]) {
					t.Fatal("endpoint binding changed caller DNS")
				}
			}
		})
	}
}
