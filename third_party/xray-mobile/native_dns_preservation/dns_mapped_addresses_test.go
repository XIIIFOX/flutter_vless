package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

type mappedDNSCases struct {
	PositiveCases         []dnsAddressCase `json:"positiveCases"`
	NativeRefusalControls []dnsAddressCase `json:"nativeRefusalControls"`
}

func mappedDNSCorpus(t *testing.T) mappedDNSCases {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("mapped DNS source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "dns-mapped-addresses.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases mappedDNSCases
	if err := json.Unmarshal(data, &cases); err != nil || len(cases.PositiveCases) != 3 || len(cases.NativeRefusalControls) != 2 {
		t.Fatal("three mapped IPv4 and two actual IPv6 DNS controls required", err)
	}
	return cases
}

// A rejected native candidate must be a real, completed refusal, rather than
// a timeout, failed executable lookup or missing native preparer.
func rejectMappedDNSCandidate(t *testing.T, source []byte) {
	t.Helper()
	directory := t.TempDir()
	input, output := filepath.Join(directory, "source.json"), filepath.Join(directory, "effective.json")
	if err := os.WriteFile(input, source, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("NATIVE_DNS_PREPARER"), "--prepare-dns-fixture",
		input, output, loopbackInterface(t), "endpoint.invalid", "127.0.0.1")
	_, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exitError) || exitError.ExitCode() != 3 {
		t.Fatal("actual IPv6 DNS did not complete a native family-boundary refusal", err)
	}
	if retained, err := os.ReadFile(input); err != nil || !bytes.Equal(retained, source) {
		t.Fatal("native refusal changed the source file", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected DNS candidate emitted an effective profile", err)
	}
}

// Decode/Build and file-only exporters only. This never starts a Core instance
// or enables an IPv6 underlay: Core itself unmaps only the exact ::ffff prefix.
func testMappedDNSAddresses(t *testing.T, native bool) {
	cases := mappedDNSCorpus(t)
	for _, tc := range cases.PositiveCases {
		t.Run(tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			literal := dnsLiteralControl(t, tc)
			expected := buildRootDNSAddresses(t, literal)
			actual := buildRootDNSAddresses(t, source)
			if !proto.Equal(expected, actual) {
				t.Fatal("mapped DNS source differs from its dotted IPv4 policy")
			}
			if tc.Name != "mapped_full_hosts_named_doh" {
				if len(actual.NameServer) != 1 || len(actual.NameServer[0].Address.Address.GetIp()) != 4 {
					t.Fatal("Core did not classify the mapped DNS server as IPv4")
				}
			}
			for _, host := range actual.StaticHosts {
				if len(host.Ip) != 1 || len(host.Ip[0]) != 4 {
					t.Fatal("Core did not retain an IPv4-only static hosts control")
				}
			}
			if len(actual.StaticHosts) == 0 {
				t.Fatal("missing mapped DNS static hosts control")
			}
			if !native {
				return
			}
			baseline := prepareEndpointAddress(t, literal)
			effective := prepareEndpointAddress(t, source)
			for _, field := range []string{"dns", "remarks", "custom"} {
				if !reflect.DeepEqual(tc.Config[field], effective[field]) {
					t.Fatal("native preparation rewrote raw mapped DNS or opaque caller data", field)
				}
			}
			prepared, err := json.Marshal(effective)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(expected, buildRootDNSAddresses(t, prepared)) {
				t.Fatal("native preparation changed the compiled DNS policy")
			}
			// Normalize only the declared mapped leaves for a whole-profile
			// comparison; every other caller/private policy field stays exact.
			var normalized map[string]any
			if err := json.Unmarshal(dnsLiteralControl(t, dnsAddressCase{Config: effective, Bindings: tc.Bindings}), &normalized); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(baseline, normalized) {
				t.Fatal("mapped DNS preparation differs beyond the declared raw addresses")
			}
			t.Log("DNS_MAPPED_IPV4_POLICY_PASS")
		})
	}
	for _, tc := range cases.NativeRefusalControls {
		t.Run(tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			compiled := buildRootDNSAddresses(t, source)
			if len(compiled.NameServer) != 1 || len(compiled.NameServer[0].Address.Address.GetIp()) != 16 {
				t.Fatal("actual IPv6 control unexpectedly became IPv4")
			}
			if native {
				rejectMappedDNSCandidate(t, source)
			}
		})
	}
}
