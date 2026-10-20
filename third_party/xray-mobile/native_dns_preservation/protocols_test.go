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

	"github.com/xtls/xray-core/infra/conf/serial"
)

type protocolCase struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

func protocolCorpus(t *testing.T) []protocolCase {
	return preparationCorpus(t, "protocols.json", 9)
}

func fullConfigCorpus(t *testing.T) []protocolCase {
	return preparationCorpus(t, "full-config.json", 6)
}

func directOnlyCorpus(t *testing.T) []protocolCase {
	return preparationCorpus(t, "direct-only.json", 2)
}

func preparationCases(t *testing.T) []protocolCase {
	return append(append(protocolCorpus(t), fullConfigCorpus(t)...), directOnlyCorpus(t)...)
}

// Preserve all logical settings except the existing, documented physical
// freedom/direct IPv4 policy. This exception must not weaken endpoint checks.
func nativeExpectedSettings(outbound map[string]any) any {
	role, _ := outbound["protocol"].(string)
	if role != "freedom" && role != "direct" {
		return outbound["settings"]
	}
	settings := map[string]any{}
	if original, ok := outbound["settings"].(map[string]any); ok {
		for key, value := range original {
			settings[key] = value
		}
	}
	settings["domainStrategy"] = "ForceIPv4"
	delete(settings, "targetStrategy")
	return settings
}

func preparationCorpus(t *testing.T, name string, count int) []protocolCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("corpus source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", name))
	if err != nil {
		t.Fatal(err)
	}
	var cases []protocolCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != count {
		t.Fatalf("expected %d focused preparation cases in %s", count, name)
	}
	return cases
}

// Decode/build only: no core.Instance, listeners, DNS or runtime initialization.
func TestProtocolCorpusBuilds(t *testing.T) {
	t.Run("Core-stats-wire", TestCLIStatsWire)
	t.Run("Core-empty-inbound-tag", testNativeRoutingEmptyInboundTag)
	t.Run("Core-android-preview-isolation", testAndroidRoutingPreviewIsolation)
	t.Run("Core-fakedns-control-closure", TestNativeFakeDNSControlClosure)
	t.Run("Core-fakedns-endpoint-override", TestNativeFakeDNSEndpointOverride)
	for _, tc := range preparationCases(t) {
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
			if tc.Name == "vless_websocket_tls" {
				assertWebSocketDictionaryData(t, data)
			}
		})
	}
	testListenAddresses(t, false)
	testAssetFiles(t, false)
	testCertificatePaths(t, false)
	testIPv6PayloadPreparation(t, false)
	testIPv6RuntimeDocumentsBuild(t)
	testSelectorTrafficPreparation(t, false)
	testLocalhostDNSTags(t, false)
	testEndpointAddresses(t, false)
	testDNSAddresses(t, false)
	testMappedDNSAddresses(t, false)
	testIPv6DNSServers(t, false)
	testDNSDataMaps(t, false)
	testTransportDataMaps(t, false)
	testTransportNone(t, false)
	testLogicalAddresses(t, false)
	testLogicalDNSFixtureIO(t)
	testFakeDNSPreparation(t, false)
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
	for _, tc := range preparationCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			prepared, _ := prepare(t, tc.Config)
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decoded.Build(); err != nil {
				t.Fatal("native preparation broke valid Core configuration", err)
			}
			if tc.Name == "vless_websocket_tls" {
				assertWebSocketDictionaryData(t, prepared)
			}
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			assertCallerServiceRoots(t, tc.Config, effective)
			if tc.Name == "vless_xhttp_penetrating_download" {
				assertPenetratingXHTTPGraph(t, tc.Config, effective)
			}
			original := tc.Config["outbounds"].([]any)
			actual := effective["outbounds"].([]any)
			for index, value := range original {
				source := value.(map[string]any)
				result := actual[index].(map[string]any)
				if result["protocol"] != source["protocol"] || result["tag"] != source["tag"] {
					t.Fatal("source handler order, role alias or tag changed")
				}
				if !reflect.DeepEqual(nativeExpectedSettings(source), result["settings"]) {
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
	testListenAddresses(t, true)
	testAssetFiles(t, true)
	testIPv6PayloadPreparation(t, true)
	testSelectorTrafficPreparation(t, true)
	testLocalhostDNSTags(t, true)
	testEndpointAddresses(t, true)
	testDNSAddresses(t, true)
	testMappedDNSAddresses(t, true)
	testIPv6DNSServers(t, true)
	testDNSDataMaps(t, true)
	testTransportDataMaps(t, true)
	testTransportNone(t, true)
	testLogicalAddresses(t, true)
	testFakeDNSPreparation(t, true)
}

func foldedRoot(object map[string]any, name string) (any, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func assertCallerServiceRoots(t *testing.T, source, effective map[string]any) {
	t.Helper()
	for _, name := range []string{"api", "stats", "policy"} {
		want, present := foldedRoot(source, name)
		if !present {
			continue
		}
		got, retained := foldedRoot(effective, name)
		wantJSON, wantErr := json.Marshal(want)
		gotJSON, gotErr := json.Marshal(got)
		if !retained || wantErr != nil || gotErr != nil || !bytes.Equal(wantJSON, gotJSON) {
			t.Fatalf("caller %s subtree changed during VPN preparation", name)
		}
	}
}
