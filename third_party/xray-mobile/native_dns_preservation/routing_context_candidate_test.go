package native_dns_preservation_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// Semantic prototype only: this is not installed in Core or a native launcher.
// A production seam must mint the binding from the exact instance/compiled
// private handler, retain it for that flow, and support legitimate UDP copies.
// Comparing a guessed caller-controlled tag alone would not establish ownership.
type routingContextCandidate struct {
	private, caller routing.Router
	input           *session.Inbound
	managedTag      string
	alias           string
	fallback        string
	revoked         bool
	handlerExists   func(string) bool
}

type routingContextAlias struct {
	routing.Context
	tag string
}

func (c routingContextAlias) GetInboundTag() string { return c.tag }

type routingContextDefault struct {
	routing.Context
	tag string
}

func (r routingContextDefault) GetOutboundTag() string       { return r.tag }
func (routingContextDefault) GetOutboundGroupTags() []string { return nil }
func (routingContextDefault) GetRuleTag() string             { return "" }

var errRoutingContextMissingDefault = errors.New("selected VPN default handler unavailable")

func (c *routingContextCandidate) PickRoute(ctx routing.Context) (routing.Route, error) {
	// Private guards see the unchanged physical context. A match/error cannot be
	// retried under caller routing or converted into an optional fallback.
	if route, err := c.private.PickRoute(ctx); err != common.ErrNoClue {
		return route, err
	}
	base, isSession := ctx.(*routing_session.Context)
	bound := !c.revoked && isSession && base.Inbound != nil && base.Inbound == c.input && base.Inbound.Tag == c.managedTag
	callerContext := ctx
	if bound && c.alias != "" {
		callerContext = routingContextAlias{Context: ctx, tag: c.alias}
	}
	route, err := c.caller.PickRoute(callerContext)
	if err != common.ErrNoClue || !bound || c.fallback == "" {
		return route, err
	}
	// This point is after the complete real caller router (including its DNS/IP
	// second pass). A removed selected handler must not fall back to handler #0.
	if !c.handlerExists(c.fallback) {
		return nil, errRoutingContextMissingDefault
	}
	return routingContextDefault{Context: callerContext, tag: c.fallback}, nil
}

func routingContextCandidateFor(t *testing.T, client *routingContextDNS, caller routing.Router) (*routingContextCandidate, *routing_session.Context) {
	t.Helper()
	private := routingContextRouter(t, client, "AsIs",
		`{"type":"field","inboundTag":["managed-input"],"ip":["198.18.0.2/32"],"port":"53","network":"tcp,udp","outboundTag":"private-dns"}`,
		`{"type":"field","inboundTag":["managed-input"],"ip":["127.0.0.1/32"],"port":"13891","network":"tcp","outboundTag":"private-probe"}`,
		`{"type":"field","inboundTag":["bootstrap-input"],"outboundTag":"private-pin"}`)
	ctx := routingContextRequest("managed-input", false)
	return &routingContextCandidate{private: private, caller: caller, input: ctx.Inbound, managedTag: "managed-input",
		alias: "caller-input", fallback: "vpn-default", handlerExists: func(tag string) bool { return tag == "vpn-default" }}, ctx
}

func TestNativeRoutingContextCandidate(t *testing.T) {
	t.Run("full-real-router-before-default", func(t *testing.T) {
		client := new(routingContextDNS)
		caller := routingContextRouter(t, client, "IPIfNonMatch",
			`{"type":"field","inboundTag":["caller-input"],"ip":["192.0.2.23/32"],"outboundTag":"caller-ip"}`)
		candidate, ctx := routingContextCandidateFor(t, client, caller)
		originalTag, originalContent := ctx.Inbound.Tag, *ctx.Content
		if got := routingContextTag(t, candidate, ctx); got != "caller-ip" || len(client.calls) != 1 {
			t.Fatalf("candidate bypassed real IPIfNonMatch: %q/%d", got, len(client.calls))
		}
		ctx.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 24}), 443)
		if got := routingContextTag(t, candidate, ctx); got != "vpn-default" {
			t.Fatalf("selected default lost after actual router miss: %q", got)
		}
		if ctx.Inbound.Tag != originalTag || !reflect.DeepEqual(*ctx.Content, originalContent) {
			t.Fatal("routing wrapper changed physical tag/content/DNS flags")
		}
		candidate.handlerExists = func(string) bool { return false }
		if _, err := candidate.PickRoute(ctx); err != errRoutingContextMissingDefault {
			t.Fatal("removed selected default silently fell back")
		}
	})
	t.Run("private-guards-and-foreign-context", func(t *testing.T) {
		client := new(routingContextDNS)
		caller := routingContextRouter(t, client, "IPIfNonMatch",
			`{"type":"field","inboundTag":["caller-input"],"outboundTag":"caller-block"}`)
		candidate, ctx := routingContextCandidateFor(t, client, caller)
		for _, target := range []net.Destination{
			net.UDPDestination(net.IPAddress([]byte{198, 18, 0, 2}), 53),
			net.TCPDestination(net.IPAddress([]byte{198, 18, 0, 2}), 53),
		} {
			ctx.Outbound.Target = target
			if got := routingContextTag(t, candidate, ctx); got != "private-dns" || len(client.calls) != 0 {
				t.Fatal("caller alias/default intercepted private virtual DNS")
			}
		}
		ctx.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), 13891)
		if got := routingContextTag(t, candidate, ctx); got != "private-probe" {
			t.Fatal("caller alias/default intercepted private readiness probe")
		}
		for _, tag := range []string{"managed-input", "caller-input", "bootstrap-input", "caller-dns-upstream"} {
			foreign := routingContextRequest(tag, false)
			foreign.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 24}), 443)
			want := ""
			if tag == "caller-input" {
				want = "caller-block"
			} else if tag == "bootstrap-input" {
				want = "private-pin"
			}
			if got := routingContextTag(t, candidate, foreign); got != want {
				t.Fatalf("foreign %q acquired managed alias/default: %q", tag, got)
			}
		}
		ctx.Inbound.Tag = "bootstrap-input"
		if got := routingContextTag(t, candidate, ctx); got != "private-pin" {
			t.Fatal("redispatched context retained managed policy over its private pin")
		}
		ctx.Inbound.Tag = "managed-input"
		ctx.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 24}), 443)
		candidate.revoked = true
		if got := routingContextTag(t, candidate, ctx); got != "" {
			t.Fatal("revoked binding retained an alias/default")
		}
	})
	t.Run("dynamic-caller-rules-not-snapshotted", func(t *testing.T) {
		client := new(routingContextDNS)
		caller := routingContextRouter(t, client, "IPIfNonMatch")
		candidate, ctx := routingContextCandidateFor(t, client, caller)
		ctx.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 24}), 443)
		if got := routingContextTag(t, candidate, ctx); got != "vpn-default" {
			t.Fatal("initial candidate default missing")
		}
		var update conf.RouterConfig
		if err := json.Unmarshal([]byte(`{"rules":[{"type":"field","ruleTag":"dynamic-rule","inboundTag":["caller-input"],"outboundTag":"dynamic-caller"}]}`), &update); err != nil {
			t.Fatal(err)
		}
		built, err := update.Build()
		if err != nil {
			t.Fatal(err)
		}
		if err := caller.AddRule(serial.ToTypedMessage(built), true); err != nil {
			t.Fatal(err)
		}
		if got := routingContextTag(t, candidate, ctx); got != "dynamic-caller" {
			t.Fatal("actual RoutingAPI-style addition was frozen out")
		}
		if err := caller.RemoveRule("dynamic-rule"); err != nil {
			t.Fatal(err)
		}
		if got := routingContextTag(t, candidate, ctx); got != "vpn-default" {
			t.Fatal("actual RoutingAPI-style removal did not restore selected default")
		}
	})
	t.Run("unexpected-router-error-preserved", func(t *testing.T) {
		unexpected := errors.New("inert unexpected router error")
		client := new(routingContextDNS)
		candidate, ctx := routingContextCandidateFor(t, client, candidateErrorRouter{err: unexpected})
		if _, err := candidate.PickRoute(ctx); err != unexpected {
			t.Fatal("caller router error was masked by selected default")
		}
	})
}

// The error control embeds the feature's unused lifecycle methods; tests invoke
// only PickRoute and must never start or close this inert adapter.
type candidateErrorRouter struct {
	routing.Router
	err error
}

func (r candidateErrorRouter) PickRoute(routing.Context) (routing.Route, error) { return nil, r.err }
