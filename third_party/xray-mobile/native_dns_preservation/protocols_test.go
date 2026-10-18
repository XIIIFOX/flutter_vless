package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

type protocolCase struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

func protocolCorpus(t *testing.T) []protocolCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("corpus source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "protocols.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []protocolCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 7 {
		t.Fatal("expected seven focused protocol preparation cases")
	}
	return cases
}

// Decode/build only: no core.Instance, listeners, DNS or runtime initialization.
func TestProtocolCorpusBuilds(t *testing.T) {
	for _, tc := range protocolCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			data, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decoded.Build(); err != nil {
				t.Fatal("source fixture is not valid pinned Core configuration", err)
			}
		})
	}
}

// File-only native preparation and Core Build. No core.Instance is created,
// and no fixture socket, DNS resolver or platform network setting is used.
func TestNativeProtocolPreparation(t *testing.T) {
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production native preparer required")
	}
	t.Run("WindowsPreparer", testNativeProtocolPreparation)
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		t.Run("ApplePreparer", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeProtocolPreparation(t) })
	}
}

func testNativeProtocolPreparation(t *testing.T) {
	for _, tc := range protocolCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			prepared, _ := prepare(t, tc.Config)
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decoded.Build(); err != nil {
				t.Fatal("native preparation broke valid Core configuration", err)
			}
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			original := tc.Config["outbounds"].([]any)
			actual := effective["outbounds"].([]any)
			for index, value := range original {
				source := value.(map[string]any)
				result := actual[index].(map[string]any)
				if result["protocol"] != source["protocol"] || result["tag"] != source["tag"] {
					t.Fatal("source handler order, role alias or tag changed")
				}
				role := source["protocol"].(string)
				if role != "freedom" && role != "direct" && !reflect.DeepEqual(source["settings"], result["settings"]) {
					t.Fatal("protocol settings or logical destination changed")
				}
				stream, ok := source["streamSettings"].(map[string]any)
				if !ok {
					continue
				}
				next := result["streamSettings"].(map[string]any)
				for _, field := range []string{"security", "tlsSettings", "realitySettings", "masqueSettings", "wsSettings", "grpcSettings", "httpupgradeSettings"} {
					if !reflect.DeepEqual(stream[field], next[field]) {
						t.Fatalf("caller transport field %s changed", field)
					}
				}
				if sourceHTTP, ok := stream["xhttpSettings"].(map[string]any); ok {
					if !reflect.DeepEqual(sourceHTTP["path"], next["xhttpSettings"].(map[string]any)["path"]) {
						t.Fatal("XHTTP path changed")
					}
					if dormant := stream["splithttpSettings"]; dormant != nil && !reflect.DeepEqual(dormant, next["splithttpSettings"]) {
						t.Fatal("inactive transport alias changed")
					}
				}
			}
		})
	}
}
