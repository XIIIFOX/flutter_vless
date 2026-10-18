package XRay

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

// Shared input corpus is checked against the pinned Core decoder/build path.
// No core is started: this cannot open listeners or change the host network.
func TestCompatibilityPortCorpus(t *testing.T) {
	data, err := os.ReadFile("../../tool/fixtures/compatibility/ports.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name        string
		Value       json.RawMessage
		Environment map[string]string
		Ports       []uint16
		Invalid     bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			// Keep host variables out of the fixture. The names are reserved to QA.
			for _, name := range []string{"flutter.vless.fixture.ports", "FLUTTER_VLESS_FIXTURE_PORTS"} {
				if value, ok := c.Environment[name]; ok {
					t.Setenv(name, value)
				} else {
					old, present := os.LookupEnv(name)
					os.Unsetenv(name)
					t.Cleanup(func() {
						if present {
							os.Setenv(name, old)
						} else {
							os.Unsetenv(name)
						}
					})
				}
			}
			profile := append([]byte(`{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":`), c.Value...)
			profile = append(profile, []byte(`,"settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}`)...)
			config, err := serial.DecodeJSONConfig(bytes.NewReader(profile))
			if err == nil {
				_, err = config.Build()
			}
			if c.Invalid {
				if err == nil {
					t.Fatal("Core unexpectedly accepted invalid fixture")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ports := make([]uint16, 0)
			for _, p := range config.InboundConfigs[0].PortList.Build().Ports() {
				if p != 0 {
					ports = append(ports, uint16(p))
				}
			}
			sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
			if !reflect.DeepEqual(ports, c.Ports) {
				t.Fatalf("ports: got %v, want %v", ports, c.Ports)
			}
		})
	}
}
