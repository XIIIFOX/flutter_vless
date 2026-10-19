package native_dns_preservation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"
)

func logicalAddressCorpus(t *testing.T) []dnsAddressCase {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("logical Address source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "logical-addresses.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the explicit path representation, including array indices. No
	// arbitrary address-shaped key or string replacement selects these fields.
	var cases []dnsAddressCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) != 4 {
		t.Fatal("four logical Address cases required", err)
	}
	return cases
}

func testLogicalAddresses(t *testing.T, native bool) {
	cases := logicalAddressCorpus(t)
	// Validate the exact runtime document offline too; constructing it needs
	// only synthetic ports and never opens a listener or Core instance.
	cases = append(cases, dnsAddressCase{Name: "runtime_material", Environment: map[string]string{
		logicalTargetEnvironment: "127.0.0.1", logicalDormantEnvironment: "127.0.0.9",
	}, Config: logicalRuntimeDocument(18083, 18053, []int{12001, 12002}), Bindings: logicalRuntimeBindings()})
	for _, tc := range cases {
		t.Run("logical_"+tc.Name, func(t *testing.T) {
			for name, value := range tc.Environment {
				t.Setenv(name, value)
			}
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			// Programmatic runtime material contains []string/int values; compare
			// with the same JSON representation returned by the native exporter.
			var original map[string]any
			if err := json.Unmarshal(source, &original); err != nil {
				t.Fatal(err)
			}
			control := dnsLiteralControl(t, tc)
			if !proto.Equal(buildEndpointAddress(t, source), buildEndpointAddress(t, control)) {
				t.Fatal("logical env Address differs from literal under pinned Core")
			}
			if !native {
				return
			}
			baseline := prepareEndpointAddress(t, control)
			t.Log("LOGICAL_ADDRESS_LITERAL_CONTROL_PASS")
			effective := prepareEndpointAddress(t, source)
			if !reflect.DeepEqual(baseline, effective) {
				t.Fatal("logical Address preparation differs from whole literal control")
			}
			for _, field := range []string{"dns", "remarks", "custom"} {
				if !reflect.DeepEqual(original[field], effective[field]) {
					t.Fatal("logical binding changed unrelated caller field", field)
				}
			}
			prepared, err := json.Marshal(effective)
			if err != nil {
				t.Fatal(err)
			}
			before := buildEndpointAddress(t, prepared)
			// The ignored alias may change too; the primary's Core precedence
			// must keep the complete compiled profile stable in the provider.
			for name := range tc.Environment {
				t.Setenv(name, "127.0.0.2")
			}
			if !proto.Equal(before, buildEndpointAddress(t, prepared)) {
				t.Fatal("prepared logical destination changed after environment handoff")
			}
			t.Log("LOGICAL_ADDRESS_ENVIRONMENT_FROZEN_PASS")
		})
	}
}
