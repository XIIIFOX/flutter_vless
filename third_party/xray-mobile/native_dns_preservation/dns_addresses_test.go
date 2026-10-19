package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

type dnsAddressBinding struct {
	Path  []string `json:"path"`
	Value string   `json:"value"`
}

type dnsAddressCase struct {
	Name        string              `json:"name"`
	Environment map[string]string   `json:"environment"`
	Bindings    []dnsAddressBinding `json:"bindings"`
	Config      map[string]any      `json:"config"`
}

func dnsAddressCorpus(t *testing.T) []dnsAddressCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("DNS Address source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "dns-addresses.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []dnsAddressCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) != 3 {
		t.Fatal("three DNS Address cases required", err)
	}
	return cases
}

func dnsLiteralControl(t *testing.T, tc dnsAddressCase) []byte {
	t.Helper()
	data, err := json.Marshal(tc.Config)
	if err != nil {
		t.Fatal(err)
	}
	var control any
	if err := json.Unmarshal(data, &control); err != nil {
		t.Fatal(err)
	}
	for _, binding := range tc.Bindings {
		var replace func(any, []string)
		replace = func(node any, path []string) {
			if len(path) == 0 {
				t.Fatal("empty DNS binding path")
			}
			switch object := node.(type) {
			case map[string]any:
				if _, exists := object[path[0]]; !exists {
					t.Fatal("missing DNS binding field", binding.Path)
				}
				if len(path) == 1 {
					object[path[0]] = binding.Value
				} else {
					replace(object[path[0]], path[1:])
				}
			case []any:
				index, err := strconv.Atoi(path[0])
				if err != nil || index < 0 || index >= len(object) {
					t.Fatal("invalid DNS binding index", binding.Path)
				}
				if len(path) == 1 {
					object[index] = binding.Value
				} else {
					replace(object[index], path[1:])
				}
			default:
				t.Fatal("invalid DNS binding path", binding.Path)
			}
		}
		replace(control, binding.Path)
	}
	data, err = json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Build alone constructs no Core instance, network engine or resolver. Only
// the hosts list produced from a JSON map is sorted; server/IP order is kept.
func buildRootDNSAddresses(t *testing.T, data []byte) *appdns.Config {
	t.Helper()
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range built.App {
		message, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if dns, ok := message.(*appdns.Config); ok {
			sort.Slice(dns.StaticHosts, func(i, j int) bool { return dns.StaticHosts[i].Domain.String() < dns.StaticHosts[j].Domain.String() })
			return dns
		}
	}
	t.Fatal("missing compiled DNS client")
	return nil
}

func testDNSAddresses(t *testing.T, native bool) {
	for _, tc := range dnsAddressCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			for name, value := range tc.Environment {
				t.Setenv(name, value)
			}
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			control := dnsLiteralControl(t, tc)
			expected := buildRootDNSAddresses(t, control)
			if !proto.Equal(expected, buildRootDNSAddresses(t, source)) {
				t.Fatal("DNS Address environment differs from literal under pinned Core")
			}
			if tc.Name == "dns_hosts" {
				found := false
				for _, host := range expected.StaticHosts {
					if host.Domain.GetCustom().Value == "mixed.invalid" {
						found = true
						if host.ProxiedDomain != "alias-target-a.invalid" || len(host.Ip) != 0 {
							t.Fatal("Core's first alias must replace all IPs")
						}
					}
				}
				if !found {
					t.Fatal("missing mixed hosts alias control")
				}
			}
			if !native {
				return
			}
			baseline := prepareEndpointAddress(t, control)
			t.Log("DNS_ADDRESS_LITERAL_CONTROL_PASS")
			effective := prepareEndpointAddress(t, source)
			if !reflect.DeepEqual(baseline, effective) {
				t.Fatal("DNS Address binding differs from whole literal profile")
			}
			if !reflect.DeepEqual(tc.Config["remarks"], effective["remarks"]) || !reflect.DeepEqual(tc.Config["custom"], effective["custom"]) {
				t.Fatal("DNS binding changed opaque caller fields")
			}
			prepared, err := json.Marshal(effective)
			if err != nil {
				t.Fatal(err)
			}
			before := buildRootDNSAddresses(t, prepared)
			if !proto.Equal(expected, before) {
				t.Fatal("prepared DNS differs from the original Core DNS policy")
			}
			for name := range tc.Environment {
				t.Setenv(name, "unreachable.invalid")
			}
			if !proto.Equal(before, buildRootDNSAddresses(t, prepared)) {
				t.Fatal("prepared DNS changed after environment handoff")
			}
			t.Log("DNS_ADDRESS_ENVIRONMENT_FROZEN_PASS")
		})
	}
}
