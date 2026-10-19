package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

// Decode/Build and the static-host matcher are inert. The system-hosts case
// reads the existing hosts file through Core Build without changing it or
// constructing a Core instance, resolver, socket or network setting.
func testDNSDataMaps(t *testing.T, native bool) {
	for _, tc := range preparationCorpus(t, "dns-data-maps.json", 5) {
		t.Run("dns_data_"+tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			expected := buildRootDNSAddresses(t, source)
			hosts, err := appdns.NewStaticHosts(expected.StaticHosts)
			if err != nil {
				t.Fatal("caller data keys are not valid Core static hosts", err)
			}
			for name, address := range map[string]string{
				"allowInsecure": "192.0.2.8", "network": "192.0.2.9",
				"xHTTPSettings": "192.0.2.10", "httpUpgradeSettings": "192.0.2.11", "splitHTTPSettings": "192.0.2.12",
			} {
				answer, err := hosts.Lookup(name, dnsfeature.IPOption{IPv4Enable: true})
				if err != nil || len(answer) != 1 || answer[0].String() != address {
					t.Fatal("Core static-host data semantics differ", name, err)
				}
			}
			if !native {
				return
			}
			effective := prepareEndpointAddress(t, source)
			wantDNS, ok := foldedRoot(tc.Config, "dns")
			if !ok || !reflect.DeepEqual(wantDNS, effective["dns"]) {
				t.Fatal("native preparation changed a caller DNS dictionary or URL")
			}
			prepared, err := json.Marshal(effective)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(expected, buildRootDNSAddresses(t, prepared)) {
				t.Fatal("native preparation changed compiled Core DNS semantics")
			}
			retained, err := json.Marshal(tc.Config)
			if err != nil || string(retained) != string(source) {
				t.Fatal("native preparation changed the caller source", err)
			}
		})
	}
}

// These strings are dictionary data in pinned Core, never active socket or
// compatibility settings. Only Build and the inert static-host matcher run.
func assertWebSocketDictionaryData(t *testing.T, data []byte) {
	t.Helper()
	document, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	stream := document.OutboundConfigs[0].StreamSetting
	message, err := stream.WSSettings.Build()
	if err != nil {
		t.Fatal(err)
	}
	headers := message.(*websocket.Config).Header
	for key, want := range map[string]string{
		"allowInsecure": "literal-header-value", "network": "MiXeD-CaSe",
		"xHTTPSettings": "literal-alias-name", "type": "xicmp",
		"Origin": "quic+local://literal.invalid",
	} {
		if headers[key] != want {
			t.Fatalf("Core WebSocket header data changed: %s", key)
		}
	}
	hosts, err := appdns.NewStaticHosts(buildRootDNSAddresses(t, data).StaticHosts)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := hosts.Lookup("type", dnsfeature.IPOption{IPv4Enable: true})
	if err != nil || len(answer) != 1 || answer[0].String() != "192.0.2.9" {
		t.Fatal("Core DNS alias named type is caller data", err)
	}
}
