package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// Decode/build only. Environment aliases use Core's simple one-rune uppercase,
// which differs from full Unicode uppercase and ASCII-only uppercase.
func TestPortEnvironmentAliases(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("port environment corpus source unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "port-env.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name        string            `json:"name"`
		Value       string            `json:"value"`
		Alias       string            `json:"alias"`
		Environment map[string]string `json:"environment"`
		Ports       []uint32          `json:"ports"`
		Invalid     bool              `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) != 8 {
		t.Fatalf("expected eight port environment cases: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			name := strings.TrimPrefix(tc.Value, "env:")
			if actual := platform.NormalizeEnvName(name); actual != tc.Alias {
				t.Fatalf("Core alias %q, want %q", actual, tc.Alias)
			}
			keys := map[string]bool{name: true, tc.Alias: true}
			for key := range tc.Environment {
				keys[key] = true
			}
			// Exact-name absence is meaningful; an empty present value must win.
			for key := range keys {
				key := key
				previous, present := os.LookupEnv(key)
				t.Cleanup(func() {
					if present {
						_ = os.Setenv(key, previous)
					} else {
						_ = os.Unsetenv(key)
					}
				})
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			for key, value := range tc.Environment {
				if err := os.Setenv(key, value); err != nil {
					t.Fatal(err)
				}
			}
			value, err := json.Marshal(tc.Value)
			if err != nil {
				t.Fatal(err)
			}
			var ports conf.PortList
			parseErr := json.Unmarshal(value, &ports)
			if tc.Invalid {
				if parseErr == nil {
					t.Fatal("invalid environment port was accepted")
				}
				return
			}
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if got := ports.Build().Ports(); !reflect.DeepEqual(got, tc.Ports) {
				t.Fatalf("Core ports %v, want %v", got, tc.Ports)
			}
			document := []byte(`{"inbounds":[{"listen":"127.0.0.1","port":` + string(value) + `,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}`)
			original := bytes.Clone(document)
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(document))
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := decoded.Build()
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := compiled.Inbound[0].ReceiverSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if got := receiver.(*proxyman.ReceiverConfig).PortList.Ports(); !reflect.DeepEqual(got, tc.Ports) {
				t.Fatalf("compiled listener ports %v, want %v", got, tc.Ports)
			}
			if !bytes.Equal(document, original) {
				t.Fatal("Core decode/build changed source bytes")
			}
		})
	}
}
