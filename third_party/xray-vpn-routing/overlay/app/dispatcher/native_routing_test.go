package dispatcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// All fixtures are inert: no Core.New, feature Start, sockets or OS resolver.
type nativeTestHandler struct{}

func (*nativeTestHandler) Tag() string { return "managed" }

type nativeTestConn struct{ n int }

func (*nativeTestConn) Read([]byte) (int, error)         { return 0, errors.New("inert read") }
func (*nativeTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*nativeTestConn) Close() error                     { return nil }
func (*nativeTestConn) LocalAddr() net.Addr              { return nil }
func (*nativeTestConn) RemoteAddr() net.Addr             { return nil }
func (*nativeTestConn) SetDeadline(time.Time) error      { return nil }
func (*nativeTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*nativeTestConn) SetWriteDeadline(time.Time) error { return nil }

type nativeCaller struct {
	routing.Router
	pick func(routing.Context) (routing.Route, error)
}

func (r nativeCaller) PickRoute(ctx routing.Context) (routing.Route, error) { return r.pick(ctx) }

func nativeFixture(t *testing.T, caller routing.Router, guards []*router.RoutingRule) (*DefaultDispatcher, context.Context, *session.Inbound, *routing.NativeRoutingOwner) {
	t.Helper()
	key := &core.InboundHandlerConfig{Tag: "managed"}
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: key, ManagedTag: "managed", AuthUser: "private", AliasEnabled: true, InboundAlias: "source", DefaultOutboundTag: "vpn"})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := ContextWithNativeVPNRouting(context.Background(), owner, guards)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(core.Instance) // identity only, never initialized/started
	seed = context.WithValue(seed, core.XrayKey(1), instance)
	handler := new(nativeTestHandler)
	input, err := owner.BindInput(seed, instance, key, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Seal(instance); err != nil {
		t.Fatal(err)
	}
	meta := &session.Inbound{Tag: "managed", Conn: new(nativeTestConn), Name: "socks", User: &protocol.MemoryUser{Email: "private"}}
	metadata := routing.NativeRoutingMetadata{Conn: meta.Conn, Tag: "managed", Name: "socks", User: "private"}
	control, end, err := input.Begin(seed, instance, handler, metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	ctx, release, err := owner.BeginRoute(control, instance, metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	ctx = session.ContextWithInbound(ctx, meta)
	d := &DefaultDispatcher{router: caller}
	if err := d.bindNativeVPNRouting(seed); err != nil {
		t.Fatal(err)
	}
	return d, ctx, meta, owner
}

func TestNativeVPNRoutingSelection(t *testing.T) {
	seen := 0
	caller := nativeCaller{pick: func(ctx routing.Context) (routing.Route, error) {
		seen++
		if ctx.GetInboundTag() != "source" || ctx.GetSkipDNSResolve() {
			t.Fatal("alias changed DNS/content semantics")
		}
		return nativeRoutingRoute{Context: ctx, tag: "caller", ruleTag: "live-rule"}, nil
	}}
	d, ctx, inbound, owner := nativeFixture(t, caller, nil)
	physical := &routing_session.Context{Inbound: inbound, Content: &session.Content{}}
	foreign := context.WithValue(ctx, core.XrayKey(1), new(core.Instance))
	if _, _, _, err := d.nativePickRoute(foreign, physical); err == nil {
		t.Fatal("foreign Core borrowed a valid flow capsule")
	}
	route, kind, handled, err := d.nativePickRoute(ctx, physical)
	if err != nil || !handled || kind != 2 || route.GetOutboundTag() != "caller" || route.GetRuleTag() != "live-rule" || seen != 1 || inbound.Tag != "managed" {
		t.Fatalf("caller selection: %v/%d/%v/%v", route, kind, handled, err)
	}
	d.router = nativeCaller{pick: func(routing.Context) (routing.Route, error) { seen++; return nil, common.ErrNoClue }}
	route, kind, handled, err = d.nativePickRoute(ctx, physical)
	if err != nil || !handled || kind != 0 || route.GetOutboundTag() != "vpn" || seen != 2 {
		t.Fatal("explicit default did not follow complete router miss")
	}
	failure := errors.New("caller failed")
	d.router = nativeCaller{pick: func(routing.Context) (routing.Route, error) { return nil, failure }}
	if _, _, _, err := d.nativePickRoute(ctx, physical); err != failure {
		t.Fatal("unexpected caller error masked by default")
	}
	d.router = nativeCaller{pick: func(routing.Context) (routing.Route, error) { _ = owner.Close(); return nil, common.ErrNoClue }}
	if _, _, _, err := d.nativePickRoute(ctx, physical); err == nil {
		t.Fatal("revocation while picking committed selected default")
	}
}

func TestNativeVPNRoutingGuards(t *testing.T) {
	rules := &router.Config{Rule: []*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "dns"}, InboundTag: []string{"managed"}, PortList: &net.PortList{Range: []*net.PortRange{{From: 53, To: 53}}}, RuleTag: "private"}}}
	d, ctx, inbound, _ := nativeFixture(t, nativeCaller{pick: func(routing.Context) (routing.Route, error) {
		t.Fatal("caller intercepted private guard")
		return nil, nil
	}}, rules.Rule)
	// Seed owns an immutable clone, not the mutable builder's rule object.
	rules.Rule[0].InboundTag[0] = "changed"
	physical := &routing_session.Context{Inbound: inbound, Outbound: &session.Outbound{Target: net.UDPDestination(net.IPAddress([]byte{198, 18, 0, 2}), 53)}}
	ctx = session.SetForcedOutboundTagToContext(ctx, "wrong-forced")
	route, kind, handled, err := d.nativePickRoute(ctx, physical)
	if err != nil || !handled || kind != 2 || route.GetOutboundTag() != "dns" || route.GetRuleTag() != "private" {
		t.Fatal("private guard did not precede forced detour")
	}
	physical.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 23}), 443)
	route, kind, handled, err = d.nativePickRoute(ctx, physical)
	if err != nil || !handled || kind != 1 || route.GetOutboundTag() != "wrong-forced" {
		t.Fatal("ordinary forced detour lost")
	}
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "http", SkipDNSResolve: true, Attributes: map[string]string{"forcedOutboundTag": "wrong-forced", "caller": "preserved"}})
	consumed := consumeNativeForcedOutbound(ctx)
	if session.GetForcedOutboundTagFromContext(consumed) != "" || session.GetForcedOutboundTagFromContext(ctx) != "wrong-forced" || !session.ContentFromContext(consumed).SkipDNSResolve || session.ContentFromContext(consumed).Attribute("caller") != "preserved" || session.ContentFromContext(consumed).Protocol != "http" {
		t.Fatal("forced tag consumption changed a sibling or unrelated content")
	}
}

func TestNativeVPNRoutingSeedValidation(t *testing.T) {
	if _, err := ContextWithNativeVPNRouting(context.Background(), nil, nil); err == nil {
		t.Fatal("nil owner accepted")
	}
	d, _, _, owner := nativeFixture(t, nil, nil)
	for _, rule := range []*router.RoutingRule{
		{TargetTag: &router.RoutingRule_Tag{Tag: "x"}, Networks: []net.Network{net.Network_TCP}},
		{TargetTag: &router.RoutingRule_BalancingTag{BalancingTag: "x"}, InboundTag: []string{"managed"}},
	} {
		if _, err := ContextWithNativeVPNRouting(context.Background(), owner, []*router.RoutingRule{rule}); err == nil {
			t.Fatal("unscoped/nonliteral guard accepted")
		}
	}
	if err := d.bindNativeVPNRouting(routing.ContextWithNativeRoutingOwner(context.Background(), owner)); err == nil {
		t.Fatal("owner without plan accepted")
	}
	if err := new(DefaultDispatcher).bindNativeVPNRouting(context.Background()); err != nil {
		t.Fatal(err)
	}
	// No-capsule imported flows remain ordinary even when their tag is equal and
	// the selected owner was revoked. No alias/default granted by tag alone.
	_ = owner.Close()
	seed := routing.ContextWithNativeRoutingOwner(context.Background(), owner)
	if _, _, handled, err := d.nativePickRoute(seed, &routing_session.Context{Inbound: &session.Inbound{Tag: "managed"}}); err != nil || handled {
		t.Fatal("imported context acquired or depended on private grant")
	}
}

type nativeLookup struct{ calls int }

func (*nativeLookup) Type() interface{} { return dns.ClientType() }
func (*nativeLookup) Start() error      { panic("pure lookup cannot start") }
func (*nativeLookup) Close() error      { panic("pure lookup cannot close") }
func (d *nativeLookup) LookupIP(_ string, _ dns.IPOption) ([]net.IP, uint32, error) {
	d.calls++
	return []net.IP{{192, 0, 2, 23}}, 60, nil
}

func TestNativeVPNRoutingRealRouter(t *testing.T) {
	lookup := new(nativeLookup)
	caller := new(router.Router)
	config := &router.Config{DomainStrategy: router.Config_IpIfNonMatch, Rule: []*router.RoutingRule{{
		TargetTag: &router.RoutingRule_Tag{Tag: "ip-match"}, InboundTag: []string{"source"},
		Ip: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{Cidr: &geodata.CIDR{Ip: []byte{192, 0, 2, 23}, Prefix: 32}}}}},
	}}}
	if err := caller.Init(context.Background(), config, lookup, nil, nil); err != nil {
		t.Fatal(err)
	}
	d, ctx, inbound, _ := nativeFixture(t, caller, nil)
	physical := &routing_session.Context{Inbound: inbound, Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("lookup.invalid"), 443)}, Content: &session.Content{}}
	route, _, handled, err := d.nativePickRoute(ctx, physical)
	if err != nil || !handled || route.GetOutboundTag() != "ip-match" || lookup.calls != 1 {
		t.Fatal("complete DNS/IP second pass was bypassed")
	}
	physical.Outbound.Target = net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 24}), 443)
	update := &router.Config{Rule: []*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "dynamic"}, InboundTag: []string{"source"}, RuleTag: "live"}}}
	if err := caller.AddRule(serial.ToTypedMessage(update), true); err != nil {
		t.Fatal(err)
	}
	route, _, _, err = d.nativePickRoute(ctx, physical)
	if err != nil || route.GetOutboundTag() != "dynamic" || route.GetRuleTag() != "live" {
		t.Fatal("live API addition lost")
	}
	if err := caller.RemoveRule("live"); err != nil {
		t.Fatal(err)
	}
	route, _, _, err = d.nativePickRoute(ctx, physical)
	if err != nil || route.GetOutboundTag() != "vpn" {
		t.Fatal("live API removal did not restore selected default")
	}
	if err := caller.AddRule(serial.ToTypedMessage(update), false); err != nil {
		t.Fatal(err)
	}
	route, _, _, err = d.nativePickRoute(ctx, physical)
	if err != nil || route.GetOutboundTag() != "dynamic" {
		t.Fatal("live API replacement lost")
	}
	if inbound.Tag != "managed" || physical.GetSkipDNSResolve() {
		t.Fatal("caller route changed session metadata")
	}
}
