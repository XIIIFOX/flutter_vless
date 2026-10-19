package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/app/dns/fakedns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

// Decode/Build and native file preparation only. The FakeDNS feature is a
// protobuf here: this does not instantiate its engine, allocate IPs or listen.
func buildFakeDNSDocument(t *testing.T, data []byte) *core.Config {
	t.Helper()
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func compiledFakeDNS(t *testing.T, config *core.Config) *fakedns.FakeDnsPoolMulti {
	t.Helper()
	var result *fakedns.FakeDnsPoolMulti
	for _, value := range config.App {
		message, err := value.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if pools, ok := message.(*fakedns.FakeDnsPoolMulti); ok {
			if result != nil {
				t.Fatal("duplicate compiled FakeDNS engine")
			}
			result = pools
		}
	}
	if result == nil {
		t.Fatal("source FakeDNS engine missing from compiled config")
	}
	return result
}

func assertManagedFakeDNSSniff(t *testing.T, built *core.Config) {
	t.Helper()
	if len(built.Inbound) == 0 {
		t.Fatal("managed inbound missing")
	}
	message, err := built.Inbound[0].ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver, ok := message.(*proxyman.ReceiverConfig)
	if !ok || receiver.SniffingSettings == nil || !receiver.SniffingSettings.Enabled || !receiver.SniffingSettings.RouteOnly {
		t.Fatal("managed FakeDNS input must retain enabled route-only sniffing")
	}
	for _, value := range receiver.SniffingSettings.DestinationOverride {
		if value == "fakedns" || value == "fakedns+others" {
			return
		}
	}
	t.Fatal("managed input cannot recover opaque FakeDNS destinations")
}

func testFakeDNSPreparation(t *testing.T, native bool) {
	t.Helper()
	cases := preparationCorpus(t, "fakedns.json", 5)
	cases = append(cases, protocolCase{Name: "runtime_opaque_material", Config: fakeDNSRuntimeDocument(18084, 18085)})
	for _, tc := range cases {
		t.Run("fakedns_"+tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			original := buildFakeDNSDocument(t, source)
			pools := compiledFakeDNS(t, original)
			if !native {
				return
			}
			prepared, _ := prepare(t, tc.Config)
			built := buildFakeDNSDocument(t, prepared)
			if !proto.Equal(pools, compiledFakeDNS(t, built)) {
				t.Fatal("native preparation replaced the caller FakeDNS engine/pools")
			}
			if !proto.Equal(buildRootDNSAddresses(t, source), buildRootDNSAddresses(t, prepared)) {
				t.Fatal("native preparation changed compiled caller DNS selection")
			}
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			wantEngine, wantPresent := foldedRoot(tc.Config, "fakedns")
			gotEngine, gotPresent := foldedRoot(effective, "fakedns")
			wantJSON, wantErr := json.Marshal(wantEngine)
			gotJSON, gotErr := json.Marshal(gotEngine)
			if wantPresent != gotPresent || wantErr != nil || gotErr != nil || !bytes.Equal(wantJSON, gotJSON) {
				t.Fatal("caller explicit/implicit/null/empty FakeDNS JSON changed")
			}
			imported, _ := tc.Config["inbounds"].([]any)
			inputs, ok := effective["inbounds"].([]any)
			if !ok || len(inputs) != len(imported)+1 {
				t.Fatal("imported input settings/sniffing/order changed for FakeDNS")
			}
			for index, input := range imported {
				if !reflect.DeepEqual(inputs[index+1], input) {
					t.Fatal("imported input settings/sniffing/order changed for FakeDNS")
				}
			}
			assertCallerServiceRoots(t, tc.Config, effective)
			assertManagedFakeDNSSniff(t, built)
			retained, err := json.Marshal(tc.Config)
			if err != nil || !bytes.Equal(retained, source) {
				t.Fatal("source FakeDNS document mutated", err)
			}
		})
	}
}
