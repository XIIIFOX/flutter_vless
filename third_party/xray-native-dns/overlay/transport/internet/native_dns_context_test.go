package internet

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

// All tests below use only values, fake features, context cancellation and pure
// destination planning. They never construct/start a Core or open a listener.
type nativeFakeDNS struct {
	ip      string
	calls   []string
	failure error
	before  func()
}

func (*nativeFakeDNS) Type() any    { return dns.ClientType() }
func (*nativeFakeDNS) Start() error { return nil }
func (*nativeFakeDNS) Close() error { return nil }
func (f *nativeFakeDNS) LookupIP(name string, _ dns.IPOption) ([]net.IP, uint32, error) {
	f.calls = append(f.calls, name)
	if f.before != nil {
		f.before()
	}
	if f.failure != nil {
		return nil, 0, f.failure
	}
	return []net.IP{net.ParseAddress(f.ip).IP()}, 123, nil
}

type nativeFakeHandler struct{ name string }

func (h *nativeFakeHandler) Tag() string                             { return h.name }
func (*nativeFakeHandler) Start() error                              { return nil }
func (*nativeFakeHandler) Close() error                              { return nil }
func (*nativeFakeHandler) Dispatch(context.Context, *transport.Link) {}
func (*nativeFakeHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (*nativeFakeHandler) ProxySettings() *serial.TypedMessage       { return nil }

type nativeFakeManager struct{ handlers map[string]outbound.Handler }

func (*nativeFakeManager) Type() any                                          { return outbound.ManagerType() }
func (*nativeFakeManager) Start() error                                       { return nil }
func (*nativeFakeManager) Close() error                                       { return nil }
func (m *nativeFakeManager) GetHandler(tag string) outbound.Handler           { return m.handlers[tag] }
func (*nativeFakeManager) GetDefaultHandler() outbound.Handler                { return nil }
func (*nativeFakeManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (*nativeFakeManager) RemoveHandler(context.Context, string) error        { return nil }
func (*nativeFakeManager) ListHandlers(context.Context) []outbound.Handler    { return nil }

func nativeFixture(t *testing.T, pin, answer string) (*NativeDNSOwner, *NativeDNSHandler, *nativeFakeDNS, *nativeFakeManager) {
	t.Helper()
	key, instance := new(int), new(int)
	owner, err := NewNativeDNSOwner([]NativeDNSBinding{{Key: key, SourceIndex: 0, ProxyType: "xray.proxy.vless.outbound.Config", TransportEndpoints: true,
		Endpoints: []NativeDNSEndpoint{{Network: net.Network_TCP, Host: "endpoint.invalid", Port: 443, Addresses: []netip.Addr{netip.MustParseAddr(pin)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	client, manager := &nativeFakeDNS{ip: answer}, &nativeFakeManager{handlers: map[string]outbound.Handler{}}
	handler, err := BindNativeDNSHandler(ContextWithNativeDNSOwner(context.Background(), owner), instance, key, "", "xray.proxy.vless.outbound.Config", client, manager)
	if err != nil {
		t.Fatal(err)
	}
	return owner, handler, client, manager
}

func nativeContext(t *testing.T, handler *NativeDNSHandler, transport bool) context.Context {
	t.Helper()
	ctx, err := handler.Context(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestNativeDNSOwnersAndOrdinaryDNSAreIsolated(t *testing.T) {
	_, a, clientA, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	_, b, clientB, _ := nativeFixture(t, "192.0.2.20", "203.0.113.20")
	wrong := &nativeFakeDNS{ip: "198.51.100.99"}
	InitSystemDialer(wrong, &nativeFakeManager{})
	defer InitSystemDialer(nil, nil)
	logical := net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443)
	for _, item := range []struct {
		handler     *NativeDNSHandler
		pin, answer string
	}{{a, "192.0.2.10", "203.0.113.10"}, {b, "192.0.2.20", "203.0.113.20"}} {
		plan, err := PrepareNativeDNSPhysical(nativeContext(t, item.handler, true), logical, nil)
		if err != nil || plan.Destination.Address.String() != item.pin {
			t.Fatalf("Wrong owned pin: %v %v", plan, err)
		}
		if logical.Address.String() != "endpoint.invalid" {
			t.Fatal("Original TLS/SNI/Host destination mutated")
		}
		caller := nativeContext(t, item.handler, false)
		plan, err = PrepareNativeDNSPhysical(caller, logical, nil)
		if err != nil || plan.Destination.Address.String() != "endpoint.invalid" {
			t.Fatal("Pins leaked into caller planning")
		}
		ips, err := LookupForIPContext(caller, "endpoint.invalid", DomainStrategy_USE_IP, nil)
		if err != nil || ips[0].String() != item.answer {
			t.Fatalf("Wrong caller DNS: %v %v", ips, err)
		}
	}
	if len(clientA.calls) != 1 || len(clientB.calls) != 1 || len(wrong.calls) != 0 {
		t.Fatal("Transport pin or scope used global/caller DNS")
	}
}

func TestNativeDNSChainKeepsLogicalTargetAndOwnManager(t *testing.T) {
	_, a, clientA, managerA := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	_, b, _, managerB := nativeFixture(t, "192.0.2.20", "203.0.113.20")
	left, right := &nativeFakeHandler{name: "next"}, &nativeFakeHandler{name: "next"}
	managerA.handlers["next"], managerB.handlers["next"] = left, right
	logical := net.TCPDestination(net.DomainAddress("carried-through-next.invalid"), 443)
	for _, item := range []struct {
		scope    *NativeDNSHandler
		expected outbound.Handler
	}{{a, left}, {b, right}} {
		ctx := nativeContext(t, item.scope, true)
		plan, err := PrepareNativeDNSPhysical(ctx, logical, &SocketConfig{DialerProxy: "next"})
		if err != nil || plan.ChainTag != "next" || plan.Destination != logical {
			t.Fatalf("Chained logical target changed: %v %v", plan, err)
		}
		handler, err := NativeDNSChainHandler(ctx, "next")
		if err != nil || handler != item.expected {
			t.Fatal("Cross-instance outbound manager used")
		}
	}
	if len(clientA.calls) != 0 {
		t.Fatal("Chain target was resolved locally")
	}
	if _, err := PrepareNativeDNSPhysical(nativeContext(t, a, true), logical, nil); !errors.Is(err, ErrNativeDNSEndpoint) {
		t.Fatal("Unowned leaf endpoint fell through")
	}
}

func TestNativeDNSSourceIndexAndPointerIdentityWithoutTags(t *testing.T) {
	keyA, keyB, instance := new(int), new(int), new(int)
	bindings := []NativeDNSBinding{{Key: keyA, SourceIndex: 0, ProxyType: "xray.proxy.freedom.Config"}, {Key: keyB, SourceIndex: 1, ProxyType: "xray.proxy.freedom.Config"}}
	owner, err := NewNativeDNSOwner(bindings)
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithNativeDNSOwner(context.Background(), owner)
	client, manager := &nativeFakeDNS{}, &nativeFakeManager{}
	for _, key := range []any{keyA, keyB} {
		if _, err := BindNativeDNSHandler(ctx, instance, key, "", "xray.proxy.freedom.Config", client, manager); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		instance, key any
		tag, typ      string
	}{{new(int), keyA, "", "xray.proxy.freedom.Config"}, {instance, new(int), "", "xray.proxy.freedom.Config"}, {instance, keyA, "changed", "xray.proxy.freedom.Config"}, {instance, keyA, "", "xray.proxy.dns.Config"}} {
		if _, err := BindNativeDNSHandler(ctx, item.instance, item.key, item.tag, item.typ, client, manager); !errors.Is(err, ErrNativeDNSIdentity) {
			t.Fatal("Forged handler identity accepted")
		}
	}
}

func TestNativeDNSMetadataIsCopiedAndEndpointRoleCannotBeForged(t *testing.T) {
	key, instance := new(int), new(int)
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	bindings := []NativeDNSBinding{{Key: key, SourceIndex: 3, Tag: "same", ProxyType: "xray.proxy.vless.outbound.Config", TransportEndpoints: true,
		Endpoints: []NativeDNSEndpoint{{Network: net.Network_TCP, Host: "endpoint.invalid", Port: 443, Addresses: addresses}}}}
	owner, err := NewNativeDNSOwner(bindings)
	if err != nil {
		t.Fatal(err)
	}
	addresses[0] = netip.MustParseAddr("192.0.2.99")
	bindings[0].Endpoints[0].Host = "changed.invalid"
	bindings[0].Tag = "changed"
	handler, err := BindNativeDNSHandler(ContextWithNativeDNSOwner(context.Background(), owner), instance, key, "same", "xray.proxy.vless.outbound.Config", &nativeFakeDNS{}, &nativeFakeManager{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareNativeDNSPhysical(nativeContext(t, handler, true), net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443), nil)
	if err != nil || plan.Destination.Address.String() != "192.0.2.10" {
		t.Fatal("Mutable metadata escaped into owner")
	}
	for _, typ := range []string{"xray.proxy.freedom.Config", "xray.proxy.dns.Config", "xray.proxy.wireguard.DeviceConfig"} {
		bindings[0].ProxyType = typ
		if _, err := NewNativeDNSOwner(bindings); !errors.Is(err, ErrNativeDNSUnsupported) {
			t.Fatal("Nontransport or pending proxy received endpoint role")
		}
	}
}

func TestNativeDNSCloseRejectsStaleScopesWithoutAffectingOtherOwner(t *testing.T) {
	owner, a, client, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	_, b, _, _ := nativeFixture(t, "192.0.2.20", "203.0.113.20")
	ctx := nativeContext(t, a, true)
	_ = owner.Close()
	if _, err := a.Context(context.Background(), true); !errors.Is(err, ErrNativeDNSClosed) {
		t.Fatal("Closed owner rebound")
	}
	if _, err := PrepareNativeDNSPhysical(ctx, net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443), nil); !errors.Is(err, ErrNativeDNSClosed) {
		t.Fatal("Stale pin reused")
	}
	if _, err := LookupForIPContext(ctx, "endpoint.invalid", DomainStrategy_USE_IP, nil); !errors.Is(err, ErrNativeDNSClosed) || len(client.calls) != 0 {
		t.Fatal("Closed owner consulted caller DNS")
	}
	if _, err := PrepareNativeDNSPhysical(nativeContext(t, b, true), net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443), nil); err != nil {
		t.Fatal("Another owner was closed")
	}
}

func TestNativeDNSCloseDuringLookupDiscardsResult(t *testing.T) {
	owner, handler, client, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	client.before = func() { _ = owner.Close() }
	if _, err := LookupForIPContext(nativeContext(t, handler, false), "endpoint.invalid", DomainStrategy_USE_IP, nil); !errors.Is(err, ErrNativeDNSClosed) {
		t.Fatal("Late DNS result escaped closed owner")
	}
}

func TestNativeDNSContextRestorationPreservesInnerCancellationNotOldRouting(t *testing.T) {
	_, handler, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	first := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: "first-request"}})
	if _, err := handler.Context(first, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	inner, cancel := context.WithDeadline(context.Background(), deadline)
	restored, err := handler.Context(inner, true)
	if err != nil {
		t.Fatal(err)
	}
	if actual, ok := restored.Deadline(); !ok || !actual.Equal(deadline) {
		t.Fatal("Inner deadline lost")
	}
	if session.OutboundsFromContext(restored) != nil {
		t.Fatal("Mutable first request copied into restored scope")
	}
	cancel()
	if _, err := PrepareNativeDNSPhysical(restored, net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443), nil); !errors.Is(err, context.Canceled) {
		t.Fatal("Inner cancellation lost")
	}
}

func TestNativeDNSOwnerCancellationReachesPhysicalOperation(t *testing.T) {
	owner, handler, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	operation, release, err := NativeDNSOperationContext(nativeContext(t, handler, true))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_ = owner.Close()
	select {
	case <-operation.Done():
	case <-time.After(time.Second):
		t.Fatal("Physical operation outlived owner cancellation")
	}
}

func TestNativeDNSMissingScopeAndResolutionFailureNeverDial(t *testing.T) {
	if _, err := DialSystem(context.Background(), net.TCPDestination(net.DomainAddress("must-not-resolve.invalid"), 443), nil); !errors.Is(err, ErrNativeDNSScope) {
		t.Fatal("Missing scope was not rejected before dial")
	}
	if _, err := LookupForIP("must-not-resolve.invalid", DomainStrategy_USE_IP, nil); !errors.Is(err, ErrNativeDNSScope) {
		t.Fatal("Contextless global resolver still available")
	}
	_, handler, client, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	client.failure = errors.New("synthetic lookup refused")
	for _, strategy := range []DomainStrategy{DomainStrategy_USE_IP, DomainStrategy_FORCE_IP} {
		_, err := DialSystem(nativeContext(t, handler, false), net.TCPDestination(net.DomainAddress("caller.invalid"), 443), &SocketConfig{DomainStrategy: strategy})
		if err == nil {
			t.Fatal("Failed scoped lookup reached OS fallback")
		}
	}
}

func TestNativeDNSUnsupportedPathsAndForeignScopeRejectBeforeNetwork(t *testing.T) {
	_, handler, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	_, other, _, _ := nativeFixture(t, "192.0.2.20", "203.0.113.20")
	if _, err := other.Context(nativeContext(t, handler, true), true); !errors.Is(err, ErrNativeDNSIdentity) {
		t.Fatal("Other instance overwrote request ownership")
	}
	for _, name := range []string{"splithttp", "grpc", "hysteria", "masque"} {
		if err := handler.ValidateTransport(&MemoryStreamConfig{ProtocolName: name}); !errors.Is(err, ErrNativeDNSUnsupported) {
			t.Fatal("Pending cached/QUIC path accepted")
		}
	}
	if _, err := PrepareNativeDNSPhysical(nativeContext(t, handler, true), net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443), &SocketConfig{AddressPortStrategy: AddressPortStrategy_SrvPortOnly}); !errors.Is(err, ErrNativeDNSUnsupported) {
		t.Fatal("SRV system lookup accepted")
	}
}

func TestNativeDNSPinSelectionHonorsStrategyAndSourceFamily(t *testing.T) {
	_, handler, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	key := nativeDNSEndpointKey(net.Network_TCP, "endpoint.invalid", 443)
	// Fixture-only access to policy internals. Production owners copy/freeze input.
	handler.binding.endpoints[key] = []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	logical := net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443)
	for _, item := range []struct {
		name     string
		strategy DomainStrategy
		gateway  net.Address
		want     string
	}{
		{"force4", DomainStrategy_FORCE_IP4, nil, "192.0.2.10"},
		{"force6", DomainStrategy_FORCE_IP6, nil, "2001:db8::10"},
		{"prefer6", DomainStrategy_USE_IP64, nil, "2001:db8::10"},
		{"prefer4", DomainStrategy_USE_IP46, nil, "192.0.2.10"},
		{"as-is-local6", DomainStrategy_AS_IS, net.ParseAddress("2001:db8::1"), "2001:db8::10"},
		{"force6-local4-conflict", DomainStrategy_FORCE_IP6, net.ParseAddress("192.0.2.1"), ""},
		{"force4-local6-conflict", DomainStrategy_FORCE_IP4, net.ParseAddress("2001:db8::1"), ""},
	} {
		t.Run(item.name, func(t *testing.T) {
			ctx := nativeContext(t, handler, true)
			if item.gateway != nil {
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Gateway: item.gateway}})
			}
			plan, err := PrepareNativeDNSPhysical(ctx, logical, &SocketConfig{DomainStrategy: item.strategy})
			if item.want == "" {
				if !errors.Is(err, ErrNativeDNSEndpoint) {
					t.Fatal("Conflicting family was accepted")
				}
				return
			}
			if err != nil || plan.Destination.Address.IP().String() != item.want {
				t.Fatalf("Wrong family: %v %v", plan, err)
			}
		})
	}
	handler.binding.endpoints[key] = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	if _, err := PrepareNativeDNSPhysical(nativeContext(t, handler, true), logical, &SocketConfig{DomainStrategy: DomainStrategy_FORCE_IP6}); !errors.Is(err, ErrNativeDNSEndpoint) {
		t.Fatal("ForceIPv6 accepted IPv4 pin")
	}
	plan, err := PrepareNativeDNSPhysical(nativeContext(t, handler, true), logical, &SocketConfig{DomainStrategy: DomainStrategy_USE_IP64})
	if err != nil || plan.Destination.Address.String() != "192.0.2.10" {
		t.Fatal("Explicit IPv4 fallback was not used")
	}
}

func TestNativeDNSStrictNameConstraintAndInvalidKeyReject(t *testing.T) {
	for _, name := range []string{"_service.example", "café.example", "a..example", "-bad.example"} {
		if _, err := nativeDNSName(name); !errors.Is(err, ErrNativeDNSEndpoint) {
			t.Fatal("Prototype name constraint not enforced")
		}
	}
	owner, _, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	if _, err := BindNativeDNSHandler(ContextWithNativeDNSOwner(context.Background(), owner), new(int), []int{1}, "", "xray.proxy.freedom.Config", &nativeFakeDNS{}, &nativeFakeManager{}); !errors.Is(err, ErrNativeDNSIdentity) {
		t.Fatal("Unhashable handler key accepted")
	}
}

func TestNativeDNSLiteralPinsCannotRewriteOrMisparseIPv6(t *testing.T) {
	key, instance := new(int), new(int)
	binding := NativeDNSBinding{Key: key, SourceIndex: 0, ProxyType: "xray.proxy.vless.outbound.Config", TransportEndpoints: true, Endpoints: []NativeDNSEndpoint{{Network: net.Network_TCP, Host: "2001:db8::10", Port: 443, Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::10")}}}}
	owner, err := NewNativeDNSOwner([]NativeDNSBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := BindNativeDNSHandler(ContextWithNativeDNSOwner(context.Background(), owner), instance, key, "", binding.ProxyType, &nativeFakeDNS{}, &nativeFakeManager{})
	if err != nil {
		t.Fatal(err)
	}
	logical := net.TCPDestination(net.ParseAddress("2001:db8::10"), 443)
	plan, err := PrepareNativeDNSPhysical(nativeContext(t, handler, true), logical, nil)
	if err != nil || plan.Destination.Address.IP().String() != "2001:db8::10" {
		t.Fatal("IPv6 literal did not survive Core Address formatting")
	}
	binding.Endpoints[0].Addresses[0] = netip.MustParseAddr("2001:db8::99")
	if _, err := NewNativeDNSOwner([]NativeDNSBinding{binding}); !errors.Is(err, ErrNativeDNSEndpoint) {
		t.Fatal("Native metadata rewrote a caller literal")
	}
}

func TestNativeDNSMalformedPrivateContextFailsWithoutPanic(t *testing.T) {
	_, handler, _, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
	for _, previous := range []nativeDNSContext{{}, {handler: &NativeDNSHandler{}}} {
		ctx := context.WithValue(context.Background(), nativeDNSHandlerKey{}, previous)
		if _, err := handler.Context(ctx, true); !errors.Is(err, ErrNativeDNSScope) {
			t.Fatal("Malformed internal scope was accepted")
		}
	}
}

func TestNativeDNSCancelledLookupDiscardsResultAndDoesNotFallback(t *testing.T) {
	for _, failure := range []error{nil, errors.New("synthetic primary lookup refused")} {
		_, handler, client, _ := nativeFixture(t, "192.0.2.10", "203.0.113.10")
		request, cancel := context.WithCancel(context.Background())
		client.before = cancel
		client.failure = failure
		owned, err := handler.Context(request, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LookupForIPContext(owned, "endpoint.invalid", DomainStrategy_USE_IP64, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("Cancelled lookup returned a late result or fallback")
		}
		if len(client.calls) != 1 {
			t.Fatal("Request cancellation initiated a fallback lookup")
		}
		if handler.owner.closed.Load() {
			t.Fatal("Request cancellation closed the owner")
		}
	}
}
