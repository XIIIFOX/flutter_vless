package nativeconfig_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/nativeconfig"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

func compiledRootDNS(t *testing.T, dns any) *core.Config {
	t.Helper()
	document := map[string]any{"outbounds": []any{map[string]any{"protocol": "freedom"}}}
	if dns != nil {
		document["dns"] = dns
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := confserial.DecodeJSONConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("Synthetic configuration decode failed")
	}
	built, err := configuration.Build()
	if err != nil {
		t.Fatal("Synthetic configuration build failed")
	}
	return built
}

func TestNativeDNSRootPathsFromActualCompiledCore(t *testing.T) {
	cases := []struct {
		name, server, host, tag string
		capability              nativeconfig.RootDNSCapability
		port                    xnet.Port
		network                 xnet.Network
		nameRequirement         bool
	}{
		{"udp-ipv4", "192.0.2.1", "192.0.2.1", "root-dns", nativeconfig.DNSRemoteUDP, 53, xnet.Network_UDP, false},
		{"udp-ipv6", "2001:db8::53", "2001:db8::53", "root-dns", nativeconfig.DNSRemoteUDP, 53, xnet.Network_UDP, false},
		{"udp-name", "resolver.invalid", "resolver.invalid", "root-dns", nativeconfig.DNSRemoteUDP, 53, xnet.Network_UDP, true},
		{"tcp-ip", "tcp://192.0.2.1:5353", "192.0.2.1", "root-dns", nativeconfig.DNSRemoteTCP, 5353, xnet.Network_TCP, false},
		{"tcp-name", "TCP://resolver.invalid", "resolver.invalid", "root-dns", nativeconfig.DNSRemoteTCP, 53, xnet.Network_TCP, true},
		{"doh-ip", "https://[2001:db8::53]/dns-query", "2001:db8::53", "root-dns", nativeconfig.DNSRemoteDoH, 443, xnet.Network_TCP, false},
		{"doh-name", "https://user:private@resolver.invalid:8443/dns-query", "resolver.invalid", "root-dns", nativeconfig.DNSRemoteDoH, 8443, xnet.Network_TCP, true},
		{"doh-idna", "https://bücher.invalid/dns-query", "xn--bcher-kva.invalid", "root-dns", nativeconfig.DNSRemoteDoH, 443, xnet.Network_TCP, true},
		{"tcp-keeps-core-name", "tcp://bücher.invalid", "bücher.invalid", "root-dns", nativeconfig.DNSRemoteTCP, 53, xnet.Network_TCP, true},
		{"h2c", "h2c://192.0.2.1/dns-query", "192.0.2.1", "root-dns", nativeconfig.DNSRemoteH2C, 443, xnet.Network_TCP, false},
		{"h2c-idna", "h2c://bücher.invalid/dns-query", "xn--bcher-kva.invalid", "root-dns", nativeconfig.DNSRemoteH2C, 443, xnet.Network_TCP, true},
		{"local-system", "localhost", "", "root-dns", nativeconfig.DNSLocalSystem, 0, xnet.Network_Unknown, false},
		{"local-case", "LOCALHOST", "", "root-dns", nativeconfig.DNSLocalSystem, 0, xnet.Network_Unknown, false},
		{"fake", "fakedns", "", "root-dns", nativeconfig.DNSFake, 0, xnet.Network_Unknown, false},
		{"local-tcp", "tcp+local://192.0.2.1", "192.0.2.1", "root-dns", nativeconfig.DNSLocalTCP, 53, xnet.Network_TCP, false},
		{"local-doh", "https+local://resolver.invalid/dns-query", "resolver.invalid", "root-dns", nativeconfig.DNSLocalDoH, 443, xnet.Network_TCP, true},
		{"local-doh-idna", "https+local://bücher.invalid/dns-query", "xn--bcher-kva.invalid", "root-dns", nativeconfig.DNSLocalDoH, 443, xnet.Network_TCP, true},
		{"local-h2c", "h2c+local://192.0.2.1/dns-query", "192.0.2.1", "root-dns", nativeconfig.DNSLocalH2C, 443, xnet.Network_TCP, false},
		{"local-h2c-idna", "h2c+local://bücher.invalid/dns-query", "xn--bcher-kva.invalid", "root-dns", nativeconfig.DNSLocalH2C, 443, xnet.Network_TCP, true},
		{"local-quic", "quic+local://[2001:db8::53]", "2001:db8::53", "root-dns", nativeconfig.DNSLocalQUIC, 853, xnet.Network_UDP, false},
		{"local-quic-name", "quic+local://resolver.invalid:8853", "resolver.invalid", "root-dns", nativeconfig.DNSLocalQUIC, 8853, xnet.Network_UDP, true},
		{"quic-keeps-core-name", "quic+local://bücher.invalid", "bücher.invalid", "root-dns", nativeconfig.DNSLocalQUIC, 853, xnet.Network_UDP, true},
		// This pin has no tls:// DNS server mode. Its fallback retains the
		// entire address as a UDP domain; do not invent DoT semantics here.
		{"unknown-scheme-not-dot", "tls://resolver.invalid:853", "tls://resolver.invalid:853", "root-dns", nativeconfig.DNSRemoteUDP, 53, xnet.Network_UDP, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			configuration := compiledRootDNS(t, map[string]any{"tag": test.tag, "servers": []string{test.server}, "hosts": map[string]string{"caller.invalid": "192.0.2.77"}})
			before := proto.Clone(configuration)
			plan, err := nativeconfig.AnalyzeRootDNS(configuration)
			if err != nil {
				t.Fatal(err)
			}
			count := 1
			if test.nameRequirement {
				count++
			}
			if len(plan.Requirements) != count {
				t.Fatalf("Unexpected requirement count: %d", len(plan.Requirements))
			}
			requirement := plan.Requirements[0]
			if requirement.Capability != test.capability || requirement.ServerIndex != 0 || requirement.AppIndex < 0 || requirement.Tag != test.tag {
				t.Fatal("Typed DNS role or source identity changed")
			}
			if requirement.Destination.Port != test.port || requirement.Destination.Network != test.network {
				t.Fatal("Wrong effective resolver network/port")
			}
			if test.host != "" {
				host := requirement.Destination.Address.String()
				if requirement.Destination.Address.Family().IsIP() {
					host = requirement.Destination.Address.IP().String()
				}
				if host != test.host {
					t.Fatal("Wrong effective resolver host")
				}
			}
			if test.nameRequirement && plan.Requirements[1].Capability != nativeconfig.DNSResolverName {
				t.Fatal("Resolver bootstrap ownership requirement lost")
			}
			if !proto.Equal(before, configuration) {
				t.Fatal("Root DNS analysis mutated caller configuration")
			}
			if nativeconfig.ValidateRootDNSCapabilities(plan, nil) == nil {
				t.Fatal("Unqualified DNS path accepted")
			}
		})
	}
}

func TestNativeDNSRootImplicitFallbackIsNeverAssumedProtected(t *testing.T) {
	for _, dns := range []any{nil, map[string]any{}, map[string]any{"hosts": map[string]string{"endpoint.invalid": "192.0.2.1"}}} {
		configuration := compiledRootDNS(t, dns)
		plan, err := nativeconfig.AnalyzeRootDNS(configuration)
		if err != nil || len(plan.Requirements) != 1 || plan.Requirements[0].Capability != nativeconfig.DNSLocalSystem || plan.Requirements[0].ServerIndex != -1 {
			t.Fatal("Missing/empty DNS must require an explicit protected system resolver")
		}
		if nativeconfig.ValidateRootDNSCapabilities(plan, map[nativeconfig.RootDNSCapability]bool{nativeconfig.DNSRemoteTCP: true}) == nil {
			t.Fatal("Remote TCP qualification cannot authorize implicit local DNS")
		}
	}
}

func TestNativeDNSRootGatePreservesPerServerIdentityAndAdditionalRequirements(t *testing.T) {
	configuration := compiledRootDNS(t, map[string]any{
		"tag": "root-tag", "queryStrategy": "UseSystem", "script": "private-script-path.lua",
		"servers": []any{
			map[string]any{"address": "tcp://192.0.2.1", "tag": "custom-tag", "queryStrategy": "UseSystem"},
			map[string]any{"address": "https://secret:credential@resolver.invalid/dns-query", "queryStrategy": "UseIPv4"},
		},
	})
	before := proto.Clone(configuration)
	plan, err := nativeconfig.AnalyzeRootDNS(configuration)
	if err != nil {
		t.Fatal(err)
	}
	want := []nativeconfig.RootDNSCapability{nativeconfig.DNSSystemFamilies, nativeconfig.DNSScript, nativeconfig.DNSSystemFamilies, nativeconfig.DNSRemoteTCP, nativeconfig.DNSRemoteDoH, nativeconfig.DNSResolverName}
	if len(plan.Requirements) != len(want) {
		t.Fatal("Lost root/server qualification requirement")
	}
	qualified := map[nativeconfig.RootDNSCapability]bool{}
	for index, capability := range want {
		if plan.Requirements[index].Capability != capability {
			t.Fatal("Wrong required capability order")
		}
		qualified[capability] = true
	}
	if plan.Requirements[3].ServerIndex != 0 || plan.Requirements[3].Tag != "custom-tag" || plan.Requirements[4].ServerIndex != 1 || plan.Requirements[4].Tag != "root-tag" {
		t.Fatal("Server/root tag precedence or source position changed")
	}
	if err := nativeconfig.ValidateRootDNSCapabilities(plan, qualified); err != nil {
		t.Fatal(err)
	}
	delete(qualified, nativeconfig.DNSResolverName)
	err = nativeconfig.ValidateRootDNSCapabilities(plan, qualified)
	var failure *nativeconfig.RootDNSError
	if !errors.As(err, &failure) || failure.ServerIndex != 1 || failure.Code != "capability-unavailable" {
		t.Fatal("Gate did not identify exact unqualified source server")
	}
	for _, private := range []string{"secret", "credential", "resolver.invalid", "private-script", "custom-tag", "root-tag"} {
		if strings.Contains(err.Error(), private) {
			t.Fatal("DNS diagnostics exposed private source values")
		}
	}
	if !proto.Equal(before, configuration) {
		t.Fatal("Capability analysis/gate changed root DNS")
	}
}

func TestNativeDNSRootMalformedCompiledInputsAreRedacted(t *testing.T) {
	valid := &appdns.Config{NameServer: []*appdns.NameServer{{Address: &xnet.Endpoint{Network: xnet.Network_UDP, Address: xnet.NewIPOrDomain(xnet.IPAddress([]byte{192, 0, 2, 1}))}}}}
	invalids := []*core.Config{
		nil,
		{App: []*serial.TypedMessage{serial.ToTypedMessage(valid), serial.ToTypedMessage(valid)}},
		{App: []*serial.TypedMessage{{Type: "xray.app.dns.Config", Value: []byte("private-invalid-proto")}}},
		{App: []*serial.TypedMessage{serial.ToTypedMessage(&appdns.Config{QueryStrategy: 99})}},
		{App: []*serial.TypedMessage{serial.ToTypedMessage(&appdns.Config{NameServer: []*appdns.NameServer{nil}})}},
		{App: []*serial.TypedMessage{serial.ToTypedMessage(&appdns.Config{NameServer: []*appdns.NameServer{{Address: &xnet.Endpoint{Address: &xnet.IPOrDomain{}}}}})}},
		{App: []*serial.TypedMessage{serial.ToTypedMessage(&appdns.Config{NameServer: []*appdns.NameServer{{Address: &xnet.Endpoint{Address: &xnet.IPOrDomain{Address: &xnet.IPOrDomain_Ip{Ip: []byte{1, 2}}}}}}})}},
	}
	for index, configuration := range invalids {
		plan, err := nativeconfig.AnalyzeRootDNS(configuration)
		if err == nil || len(plan.Requirements) != 0 || strings.Contains(err.Error(), "private") {
			t.Fatalf("Malformed case %d accepted or exposed source", index)
		}
	}
}

func TestNativeDNSRootRejectsContradictoryFamiliesBeforeConstruction(t *testing.T) {
	configuration := compiledRootDNS(t, map[string]any{"queryStrategy": "UseIPv4", "servers": []any{map[string]any{"address": "192.0.2.1", "queryStrategy": "UseIPv6"}}})
	_, err := nativeconfig.AnalyzeRootDNS(configuration)
	var failure *nativeconfig.RootDNSError
	if !errors.As(err, &failure) || failure.Code != "empty-query-families" || failure.ServerIndex != 0 {
		t.Fatal("Contradictory Core DNS query families need precise source error")
	}
}

func TestNativeDNSHTTPResolverHostMatchesToolchainCanonicalAddress(t *testing.T) {
	// No Core instance, resolver or socket: the custom dial callback records
	// net/http's canonical address and immediately returns a fixed error.
	for _, address := range []string{
		"https://bücher.invalid/dns-query",
		"https://例え.テスト:8443/dns-query",
		"https://ascii_name.invalid/dns-query",
		"https://[2001:db8::53]:8443/dns-query",
	} {
		t.Run(address, func(t *testing.T) {
			plan, err := nativeconfig.AnalyzeRootDNS(compiledRootDNS(t, map[string]any{"servers": []string{address}}))
			if err != nil {
				t.Fatal(err)
			}
			captured := make(chan string, 1)
			transport := &http.Transport{DialContext: func(_ context.Context, _, destination string) (net.Conn, error) {
				select {
				case captured <- destination:
				default:
				}
				return nil, errors.New("synthetic dial refused before resolver/socket")
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Get(address)
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("Synthetic no-socket dial unexpectedly succeeded")
			}
			select {
			case destination := <-captured:
				if destination != plan.Requirements[0].Destination.NetAddr() {
					t.Fatal("DNS metadata differs from selected Go toolchain's HTTP dial address")
				}
			default:
				t.Fatal("Toolchain did not reach the synthetic dial callback")
			}
		})
	}
}
