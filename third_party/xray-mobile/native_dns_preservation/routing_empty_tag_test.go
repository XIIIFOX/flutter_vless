package native_dns_preservation_test

import (
	"testing"

	"github.com/xtls/xray-core/app/router"
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
