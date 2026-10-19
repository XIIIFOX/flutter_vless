package XRay

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

func TestPreflightEnvironmentIsolation(t *testing.T) {
	const existing = "FLVLESS_PREFLIGHT_ENV_EXISTING"
	const absent = "FLVLESS_PREFLIGHT_ENV_ABSENT"
	t.Setenv(existing, "working-session")
	prior, wasPresent := os.LookupEnv(absent)
	if err := os.Unsetenv(absent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if wasPresent {
			_ = os.Setenv(absent, prior)
		} else {
			_ = os.Unsetenv(absent)
		}
	})
	for _, tc := range []struct {
		name string
		json string
		want int64
	}{
		{"absent", `{}`, 0},
		{"null", `{"env":null}`, 0},
		{"empty", `{"env":{}}`, 0},
		{"replace-existing", `{"env":{"` + existing + `":"candidate"}}`, 5},
		{"introduce-key", `{"env":{"` + absent + `":"candidate"}}`, 5},
		{"null-clears-existing", `{"env":{"` + existing + `":null}}`, 5},
		{"null-introduces-empty", `{"env":{"` + absent + `":null}}`, 5},
		{"folded-field", `{"EnV":{"` + existing + `":"candidate"}}`, 5},
		{"invalid-key", `{"env":{"invalid=key":"candidate"}}`, 5},
		{"mixed-invalid-key", `{"env":{"` + existing + `":"candidate","":"invalid"}}`, 5},
		{"before-static-build-failure", `{"env":{"` + existing + `":"candidate"},"outbounds":[{"protocol":"private-canary"}]}`, 5},
		{"static-build-failure", `{"outbounds":[{"protocol":"private-canary"}]}`, 3 | 2<<8 | 1<<16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reset only test-owned keys so every case starts with the same
			// present/absent state, including when exposing the old mutation bug.
			if err := os.Setenv(existing, "working-session"); err != nil {
				t.Fatal(err)
			}
			if err := os.Unsetenv(absent); err != nil {
				t.Fatal(err)
			}
			beforeEnvironment := os.Environ()
			slices.Sort(beforeEnvironment)
			input := []byte(tc.json)
			original := append([]byte(nil), input...)
			beforeRuntime := coreInstance
			got := CheckPrivate(input)
			afterEnvironment := os.Environ()
			slices.Sort(afterEnvironment)
			if !slices.Equal(beforeEnvironment, afterEnvironment) {
				t.Error("CheckPrivate changed the process environment")
			}
			if !bytes.Equal(input, original) || coreInstance != beforeRuntime {
				t.Error("CheckPrivate changed caller data or the existing runtime")
			}
			if got != tc.want {
				t.Errorf("closed result: got %d, want %d", got, tc.want)
			}
			// The shared privacy path must retain Env for StartPrivate. This
			// interim refusal belongs to CheckPrivate, not profile rewriting.
			prepared, _, _, err := privateConfig(input)
			if err != nil {
				t.Fatal(err)
			}
			var source, candidate map[string]json.RawMessage
			if json.Unmarshal(input, &source) != nil || json.Unmarshal(prepared, &candidate) != nil {
				t.Fatal("privacy document is not JSON")
			}
			for key, value := range source {
				if key == "env" || key == "EnV" {
					var expected, retained any
					if json.Unmarshal(value, &expected) != nil || json.Unmarshal(candidate[key], &retained) != nil || !reflect.DeepEqual(expected, retained) {
						t.Error("privacy preparation rewrote the caller Env feature")
					}
				}
			}
		})
	}
}

func TestPreflightUsesPinnedCoreWithoutBinding(t *testing.T) {
	// Keep the requested port occupied. A check must still succeed because it
	// validates a document instead of attempting to start its listeners.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := []byte(`{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":` + strconv.Itoa(port) + `}],"outbounds":[{"protocol":"freedom"}]}`)
	original := append([]byte(nil), config...)
	before := coreInstance
	if code := CheckPrivate(config); code != 0 {
		t.Fatalf("valid Core config: code %d", code)
	}
	if coreInstance != before {
		t.Fatal("Preflight replaced the active runtime")
	}
	if !bytes.Equal(config, original) {
		t.Fatal("Preflight changed the caller's document")
	}
	if code := CheckPrivate([]byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"},{"protocol":"private-error-canary"}]}`)); code != 3|(2<<8)|(2<<16) {
		t.Fatalf("outbound location: %d", code)
	}
	if code := CheckPrivate([]byte(`{"inbounds":[{"protocol":"private-error-canary","port":10808}],"outbounds":[{"protocol":"freedom"}]}`)); code != 3|(1<<8)|(1<<16) {
		t.Fatalf("inbound location: %d", code)
	}
	if CheckPrivate([]byte(`not-json`)) != 1 {
		t.Fatal("invalid JSON must fail without starting Core")
	}
}

func TestPreflightReportsClosedStages(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want int64
	}{
		{"empty-document", `{}`, 0},
		{"null", `null`, 1},
		{"ambiguous-policy", `{"log":{},"LOG":{}}`, 1},
		{"port-type", `{"inbounds":[{"protocol":"socks","port":true}]}`, 2},
		{"missing-certificate", `{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/missing/private-canary.pem","keyFile":"/missing/private-canary.key"}]}}}]}`, 3 | (2 << 8) | (1 << 16)},
		{"custom-network", `{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"private-canary"}}]}`, 3 | (2 << 8) | (1 << 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckPrivate([]byte(tc.json)); got != tc.want {
				t.Fatalf("closed result: got %d, want %d", got, tc.want)
			}
		})
	}
}
