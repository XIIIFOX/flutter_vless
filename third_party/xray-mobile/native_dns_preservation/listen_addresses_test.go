package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/infra/conf/serial"
)

type listenAddressCase struct {
	Name               string            `json:"name"`
	Listen             string            `json:"listen"`
	Environment        map[string]string `json:"environment"`
	WindowsEnvironment map[string]string `json:"windowsEnvironment"`
	Resolved           string            `json:"resolved"`
	WindowsResolved    string            `json:"windowsResolved"`
	Port               string            `json:"port"`
	Unix               bool              `json:"unix"`
	Invalid            bool              `json:"invalid"`
}

func listenAddressCorpus(t *testing.T) []listenAddressCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("corpus source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "listen-addresses.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []listenAddressCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) != 6 {
		t.Fatal("six listener address cases required", err)
	}
	return cases
}

// Scope fixture variables to this child test process. Empty and absent are
// different under Core's exact-name/normalized-alias lookup contract.
func listenEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	for _, name := range []string{"FLUTTER_VLESS_FIXTURE_LISTEN", "flutter.vless.fixture.listen", " flutter.vless.fixture.listen ", "FLUTTER_VLESS_FIXTURE_SECOND_LISTEN"} {
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
	for name, value := range values {
		t.Setenv(name, value)
	}
}

// Only Decode/Build and file-only native exporters. No Core instance, Unix
// socket or network listener is created, including for the full port range.
func testListenAddresses(t *testing.T, native bool) {
	for _, tc := range listenAddressCorpus(t) {
		if native && tc.Invalid {
			// The source Build negative control is in TestProtocolCorpusBuilds;
			// platform pure tests separately require nested-env binding rejection.
			continue
		}
		t.Run("listen_"+tc.Name, func(t *testing.T) {
			environment, resolved := tc.Environment, tc.Resolved
			if runtime.GOOS == "windows" && tc.WindowsEnvironment != nil {
				environment, resolved = tc.WindowsEnvironment, tc.WindowsResolved
			}
			listenEnvironment(t, environment)
			inbound := map[string]any{"tag": "caller-listen", "protocol": "socks", "listen": tc.Listen,
				"port": tc.Port, "settings": map[string]any{"auth": "noauth", "udp": false}}
			source := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{inbound},
				"dns": map[string]any{"queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}},
				"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "http", "settings": map[string]any{"address": "endpoint.invalid", "port": 443}},
					map[string]any{"tag": "direct", "protocol": "freedom"}}}
			data, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			if native {
				data, _ = prepare(t, source)
				var effective map[string]any
				if err := json.Unmarshal(data, &effective); err != nil {
					t.Fatal(err)
				}
				retained := false
				for _, input := range effective["inbounds"].([]any) {
					actual := input.(map[string]any)
					if actual["tag"] != "caller-listen" {
						continue
					}
					want := map[string]any{"tag": "caller-listen", "protocol": "socks", "listen": resolved,
						"port": tc.Port, "settings": map[string]any{"auth": "noauth", "udp": false}}
					a, _ := json.Marshal(actual)
					b, _ := json.Marshal(want)
					if !bytes.Equal(a, b) {
						t.Fatal("listener binding changed fields beyond the environment address")
					}
					retained = true
				}
				if !retained {
					t.Fatal("caller listener disappeared")
				}
			}
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			built, err := decoded.Build()
			if tc.Invalid {
				if err == nil {
					t.Fatal("Core recursively expanded a listener environment address")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			index := 0
			if native {
				index = 1 // Native adapters prepend their private SOCKS listener.
			}
			if decoded.InboundConfigs[index].ListenOn.String() != resolved {
				t.Fatal("Core listener address differs from the environment snapshot")
			}
			receiver, err := built.Inbound[index].ReceiverSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			ports := receiver.(*proxyman.ReceiverConfig).PortList
			if tc.Unix && ports != nil || !tc.Unix && (ports == nil || len(ports.Ports()) != 3) {
				t.Fatal("Core Unix/IP listener port semantics changed")
			}
		})
	}
}
