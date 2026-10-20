package native_dns_preservation_test

import (
	"encoding/json"
	"reflect"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

// Only Decode/Build and Core's in-memory static-host matcher run here. This
// test never constructs a Core instance, DNS client, listener or socket.
func testDNSStaticAliases(t *testing.T, native bool) {
	type answer struct {
		query string
		ips   []string
	}
	answers := map[string]answer{
		"doh_alias_ipv4":   {"doh.example", []string{"192.0.2.53"}},
		"tcp_alias_ipv6":   {"resolver.example", []string{"2001:db8::53"}},
		"h2c_five_aliases": {"resolver.example", []string{"2001:db8::53"}},
		"bare_alias_ipv4":  {"resolver.example", []string{"192.0.2.53", "192.0.2.54"}},
	}
	seen := make(map[string]bool)
	for _, tc := range preparationCorpus(t, "dns-static-aliases.json", 4) {
		t.Run("dns_static_alias_"+tc.Name, func(t *testing.T) {
			want, ok := answers[tc.Name]
			if !ok || seen[tc.Name] {
				t.Fatal("unknown or duplicate static alias corpus case")
			}
			seen[tc.Name] = true
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			expected := buildRootDNSAddresses(t, source)
			hosts, err := appdns.NewStaticHosts(expected.StaticHosts)
			if err != nil {
				t.Fatal("caller static aliases are not valid Core hosts", err)
			}
			resolved, err := hosts.Lookup(want.query, dnsfeature.IPOption{IPv4Enable: true, IPv6Enable: true})
			if err != nil || len(resolved) != len(want.ips) {
				t.Fatal("Core static alias did not reach its exact terminal addresses", err)
			}
			for index, address := range resolved {
				if !address.Family().IsIP() || address.IP().String() != want.ips[index] {
					t.Fatal("Core static alias terminal family/address/order changed")
				}
			}
			if native {
				effective := prepareEndpointAddress(t, source)
				callerDNS, exists := foldedRoot(tc.Config, "dns")
				if !exists || !reflect.DeepEqual(callerDNS, effective["dns"]) ||
					!reflect.DeepEqual(tc.Config["custom"], effective["custom"]) {
					t.Fatal("native preparation changed caller DNS/custom dictionaries or URLs")
				}
				prepared, err := json.Marshal(effective)
				if err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(expected, buildRootDNSAddresses(t, prepared)) {
					t.Fatal("native preparation changed full compiled Core DNS policy")
				}
			}
			retained, err := json.Marshal(tc.Config)
			if err != nil || string(retained) != string(source) {
				t.Fatal("static alias preparation changed caller source bytes", err)
			}
			t.Logf("DNS_STATIC_ALIAS_PASS native=%t case=%s", native, tc.Name)
		})
	}
	if len(seen) != len(answers) {
		t.Fatal("all four static alias cases must execute")
	}
}
