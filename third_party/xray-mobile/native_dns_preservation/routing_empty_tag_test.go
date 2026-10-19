package native_dns_preservation_test

import (
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// Ordinary Core deliberately excludes empty inbound tags from matching. An
// explicitly selected untagged source must preserve that behavior; an empty
// alias is not a tagged caller input with an empty-string matching rule.
func testNativeRoutingEmptyInboundTag(t *testing.T) {
	const emptyExpected = "" // ErrNoClue: dispatch may then use its separately selected default.
	for _, actual := range []string{"", "managed", "caller"} {
		context := routingContextRequest(actual, false)
		if router.NewInboundTagMatcher([]string{""}).Apply(context) {
			t.Fatal("empty selector matched an ordinary Core inbound")
		}
		if got := router.NewInboundTagMatcher([]string{"", "caller"}).Apply(context); got != (actual == "caller") {
			t.Fatalf("tagged positive control differs for %q", actual)
		}
	}
	client := new(routingContextDNS)
	emptyRule := routingContextRouter(t, client, "AsIs",
		`{"type":"field","inboundTag":[""],"domain":["full:route.invalid"],"outboundTag":"alias"}`)
	taggedRule := routingContextRouter(t, client, "AsIs",
		`{"type":"field","inboundTag":["caller"],"domain":["full:route.invalid"],"outboundTag":"alias"}`)
	for name, context := range map[string]routing.Context{
		"original-untagged":    routingContextRequest("", false),
		"explicit-empty-alias": routingContextAlias{Context: routingContextRequest("managed", false), tag: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := routingContextTag(t, emptyRule, context); got != emptyExpected {
				t.Fatalf("ordinary Core empty-tag route=%q, fixture expected=%q", got, emptyExpected)
			}
		})
	}
	if got := routingContextTag(t, taggedRule, routingContextAlias{Context: routingContextRequest("managed", false), tag: "caller"}); got != "alias" {
		t.Fatal("tagged source alias positive control failed")
	}
	if len(client.calls) != 0 {
		t.Fatal("inert empty-tag test unexpectedly requested DNS")
	}
}

// Android captures OS traffic as well as the test client. A marker origin only
// understands its controlled port; other ports must not consume its HTTP worker.
// This tests the fixture's caller rules with the real inert Core router. It does
// not identify which connection caused a previous device timeout.
func testAndroidRoutingPreviewIsolation(t *testing.T) {
	const block = `{"type":"field","port":"1-18082,18084-65535","outboundTag":"blocked-first"}`
	const dnsGuard = `{"type":"field","inboundTag":["managed"],"ip":["198.18.0.2/32"],"port":"53","network":"tcp,udp","outboundTag":"private-dns"}`
	const probeGuard = `{"type":"field","inboundTag":["managed"],"ip":["198.51.100.1/32"],"port":"34567","network":"tcp","outboundTag":"private-probe"}`
	for _, tag := range []string{"caller", "", "managed"} {
		t.Run("source-"+tag, func(t *testing.T) {
			client := new(routingContextDNS)
			alias := `{"type":"field","inboundTag":["caller"],"outboundTag":"alias-marker"}`
			if tag == "" {
				alias = `{"type":"field","inboundTag":[""],"outboundTag":"alias-marker"}`
			}
			caller := routingContextRouter(t, client, "AsIs", block, alias)
			guarded := routingContextRouter(t, client, "AsIs", dnsGuard, probeGuard, block, alias)
			request := func(inbound, address string, port net.Port) routing.Context {
				ctx := routingContextRequest(inbound, false)
				ctx.Outbound.Target = net.TCPDestination(net.ParseAddress(address), port)
				return ctx
			}
			for _, port := range []net.Port{80, 443, 53, 34567} {
				if got := routingContextTag(t, caller, request(tag, "10.0.2.2", port)); got != "blocked-first" {
					t.Fatalf("uncontrolled port %d reached %q", port, got)
				}
			}
			want := "" // Complete caller miss lets the factory choose its explicit default.
			if tag == "caller" {
				want = "alias-marker"
			}
			if got := routingContextTag(t, caller, request(tag, "10.0.2.2", 18083)); got != want {
				t.Fatalf("controlled alias/default path changed: got %q, want %q", got, want)
			}
			for _, probe := range []struct {
				address string
				port    net.Port
				want    string
			}{{"198.18.0.2", 53, "private-dns"}, {"198.51.100.1", 34567, "private-probe"}} {
				if got := routingContextTag(t, guarded, request("managed", probe.address, probe.port)); got != probe.want {
					t.Fatalf("private guard must precede caller block: got %q, want %q", got, probe.want)
				}
			}
			if len(client.calls) != 0 {
				t.Fatal("inert fixture isolation unexpectedly requested DNS")
			}
		})
	}
}
