package outbound

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Pure Handler function tests: no Core instance is constructed or started, no
// transport/socket is used. The injected test transport returns a sentinel.
type nativeHandlerDNS struct{ calls int }

func (*nativeHandlerDNS) Type() any    { return dns.ClientType() }
func (*nativeHandlerDNS) Start() error { return nil }
func (*nativeHandlerDNS) Close() error { return nil }
func (d *nativeHandlerDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	d.calls++
	return []net.IP{net.ParseAddress("203.0.113.40").IP()}, 123, nil
}

type nativeHandlerManager struct{ featureoutbound.Manager }
type nativeEmptyReader struct{}

func (*nativeEmptyReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }

type nativeDiscardWriter struct{}

func (*nativeDiscardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

type nativeInspectProxy struct {
	check func(context.Context)
	calls int
}

func (p *nativeInspectProxy) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	p.calls++
	p.check(ctx)
	return nil
}

func nativeHandlerFixture(t *testing.T) (*internet.NativeDNSOwner, *internet.NativeDNSHandler, *nativeHandlerDNS) {
	t.Helper()
	key, instance := new(int), new(int)
	owner, err := internet.NewNativeDNSOwner([]internet.NativeDNSBinding{{Key: key, SourceIndex: 1, ProxyType: "xray.proxy.vless.outbound.Config", TransportEndpoints: true,
		Endpoints: []internet.NativeDNSEndpoint{{Network: net.Network_TCP, Host: "endpoint.invalid", Port: 443, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.40")}}}}})
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeHandlerDNS{}
	scope, err := internet.BindNativeDNSHandler(internet.ContextWithNativeDNSOwner(context.Background(), owner), instance, key, "", "xray.proxy.vless.outbound.Config", client, &nativeHandlerManager{})
	if err != nil {
		t.Fatal(err)
	}
	return owner, scope, client
}

func TestNativeDNSHandlerDispatchRestoresCallerRole(t *testing.T) {
	_, scope, client := nativeHandlerFixture(t)
	logical := net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443)
	inspector := &nativeInspectProxy{check: func(ctx context.Context) {
		plan, err := internet.PrepareNativeDNSPhysical(ctx, logical, nil)
		if err != nil || plan.Destination.Address.String() != "endpoint.invalid" {
			t.Fatal("Dispatch carried endpoint role into caller DNS")
		}
		ips, err := internet.LookupForIPContext(ctx, "endpoint.invalid", internet.DomainStrategy_USE_IP, nil)
		if err != nil || ips[0].String() != "203.0.113.40" {
			t.Fatal("Dispatch did not restore its own caller DNS")
		}
	}}
	handler := &Handler{nativeDNS: scope, proxy: inspector}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: logical, OriginalTarget: logical}})
	ctx = session.ContextWithContent(ctx, &session.Content{})
	// Simulate an upstream transport scope handed to a chained Handler.Dispatch.
	ctx, err := scope.Context(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	handler.Dispatch(ctx, &transport.Link{Reader: &nativeEmptyReader{}, Writer: &nativeDiscardWriter{}})
	if inspector.calls != 1 || client.calls != 1 {
		t.Fatal("Dispatch did not run exactly one ordinary scoped lookup")
	}
}

func TestNativeDNSHandlerDialRestoresDetachedOwnershipAndOriginalDestination(t *testing.T) {
	owner, scope, client := nativeHandlerFixture(t)
	logical := net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443)
	sentinel := errors.New("synthetic transport; no socket opened")
	calls := 0
	name := "native-owned-dial-fixture"
	if err := internet.RegisterTransportDialer(name, func(ctx context.Context, dest net.Destination, _ *internet.MemoryStreamConfig) (stat.Connection, error) {
		calls++
		if dest != logical {
			t.Fatal("TLS/Host destination was rewritten above physical planning")
		}
		plan, err := internet.PrepareNativeDNSPhysical(ctx, dest, nil)
		if err != nil || plan.Destination.Address.String() != "192.0.2.40" {
			t.Fatal("Detached Handler.Dial lost its endpoint owner")
		}
		return nil, sentinel
	}); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{nativeDNS: scope, streamSettings: &internet.MemoryStreamConfig{ProtocolName: name}}
	if _, err := handler.Dial(context.Background(), logical); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if calls != 1 || client.calls != 0 {
		t.Fatal("Detached physical pin used caller DNS")
	}
	_ = owner.Close()
	if _, err := handler.Dial(context.Background(), logical); !errors.Is(err, internet.ErrNativeDNSClosed) {
		t.Fatal("Closed owner reached transport")
	}
	if calls != 1 {
		t.Fatal("Transport called after owner close")
	}
}

func TestNativeDNSHandlerDispatchAfterOwnerCloseNeverCallsProxy(t *testing.T) {
	owner, scope, _ := nativeHandlerFixture(t)
	inspector := &nativeInspectProxy{check: func(context.Context) { t.Fatal("Closed owner reached proxy") }}
	handler := &Handler{nativeDNS: scope, proxy: inspector}
	_ = owner.Close()
	handler.Dispatch(context.Background(), &transport.Link{Reader: &nativeEmptyReader{}, Writer: &nativeDiscardWriter{}})
	if inspector.calls != 0 {
		t.Fatal("Closed owner dispatched request")
	}
}

func TestNativeDNSHandlerOwnerCloseCancelsPendingTransportHandshake(t *testing.T) {
	owner, scope, _ := nativeHandlerFixture(t)
	entered := make(chan struct{})
	finished := make(chan error, 1)
	name := "native-owned-handshake-fixture"
	if err := internet.RegisterTransportDialer(name, func(ctx context.Context, _ net.Destination, _ *internet.MemoryStreamConfig) (stat.Connection, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{nativeDNS: scope, streamSettings: &internet.MemoryStreamConfig{ProtocolName: name}}
	go func() {
		_, err := handler.Dial(context.Background(), net.TCPDestination(net.DomainAddress("endpoint.invalid"), 443))
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Synthetic transport did not enter")
	}
	_ = owner.Close()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("Pending handshake did not receive cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Pending handshake survived owner close")
	}
}
