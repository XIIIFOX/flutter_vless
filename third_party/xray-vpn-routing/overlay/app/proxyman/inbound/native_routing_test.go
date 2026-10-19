package inbound

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type nativeRoutingFakeProxy struct {
	process func(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
	close   func() error
}

func (*nativeRoutingFakeProxy) Network() []net.Network { return []net.Network{net.Network_TCP} }
func (p *nativeRoutingFakeProxy) Process(ctx context.Context, n net.Network, conn stat.Connection, d routing.Dispatcher) error {
	return p.process(ctx, n, conn, d)
}
func (p *nativeRoutingFakeProxy) Close() error {
	if p.close != nil {
		return p.close()
	}
	return nil
}

// This connection is a pure in-memory cancellation signal, not a socket/pipe.
type nativeRoutingFakeConn struct {
	closed chan struct{}
	once   sync.Once
	count  atomic.Int32
}

func newNativeRoutingFakeConn() *nativeRoutingFakeConn {
	return &nativeRoutingFakeConn{closed: make(chan struct{})}
}
func (c *nativeRoutingFakeConn) Close() error {
	c.once.Do(func() { c.count.Add(1); close(c.closed) })
	return nil
}
func (c *nativeRoutingFakeConn) Read([]byte) (int, error)       { <-c.closed; return 0, io.EOF }
func (*nativeRoutingFakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (*nativeRoutingFakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*nativeRoutingFakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*nativeRoutingFakeConn) SetDeadline(time.Time) error      { return nil }
func (*nativeRoutingFakeConn) SetReadDeadline(time.Time) error  { return nil }
func (*nativeRoutingFakeConn) SetWriteDeadline(time.Time) error { return nil }

func nativeRoutingInboundFixture(t *testing.T) (context.Context, *core.InboundHandlerConfig, *AlwaysOnInboundHandler, *routing.NativeRoutingOwner, *nativeRoutingFakeProxy) {
	t.Helper()
	receiver := &proxyman.ReceiverConfig{Listen: net.NewIPOrDomain(net.LocalHostIP), PortList: &net.PortList{Range: []*net.PortRange{{From: 17891, To: 17891}}}}
	settings := &socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"private-user": "synthetic-password"}, UdpEnabled: true}
	key := &core.InboundHandlerConfig{Tag: "managed", ReceiverSettings: serial.ToTypedMessage(receiver), ProxySettings: serial.ToTypedMessage(settings)}
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: key, ManagedTag: "managed", AuthUser: "private-user", AliasEnabled: true, InboundAlias: "caller"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	// The zero value is only an opaque identity. No Core constructor/features run.
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	ctx = routing.ContextWithNativeRoutingOwner(ctx, owner)
	p := &nativeRoutingFakeProxy{process: func(context.Context, net.Network, stat.Connection, routing.Dispatcher) error { return nil }}
	h := &AlwaysOnInboundHandler{tag: key.Tag, receiverConfig: receiver, proxyConfig: settings, proxy: p}
	h.workers = []worker{&tcpWorker{address: net.LocalHostIP, port: 17891, tag: key.Tag, proxy: p, ctx: ctx}}
	return ctx, key, h, owner, p
}

func TestNativeRoutingInputBinding(t *testing.T) {
	t.Run("ordinary-handler-unchanged", func(t *testing.T) {
		ctx, key, h, owner, p := nativeRoutingInboundFixture(t)
		w := h.workers[0]
		foreign := proto.Clone(key).(*core.InboundHandlerConfig)
		if err := bindNativeRoutingInput(ctx, foreign, h); err != nil || h.proxy != p || h.workers[0] != w {
			t.Fatal("unselected equal-tag handler changed")
		}
		_ = owner.Close()
		if err := bindNativeRoutingInput(ctx, foreign, h); err != nil {
			t.Fatal("closed selected owner broke ordinary handler construction")
		}
		if err := bindNativeRoutingInput(context.Background(), key, h); err != nil || h.proxy != p {
			t.Fatal("opt-out Core behavior changed")
		}
	})
	t.Run("selected-shape-validation", func(t *testing.T) {
		for name, change := range map[string]func(*AlwaysOnInboundHandler){
			"public-listen":  func(h *AlwaysOnInboundHandler) { h.receiverConfig.Listen = net.NewIPOrDomain(net.AnyIP) },
			"multiple-ports": func(h *AlwaysOnInboundHandler) { h.receiverConfig.PortList.Range[0].To++ },
			"no-auth":        func(h *AlwaysOnInboundHandler) { h.proxyConfig.(*socks.ServerConfig).AuthType = socks.AuthType_NO_AUTH },
			"empty-password": func(h *AlwaysOnInboundHandler) { h.proxyConfig.(*socks.ServerConfig).Accounts["private-user"] = "" },
			"different-policy-user": func(h *AlwaysOnInboundHandler) {
				h.proxyConfig.(*socks.ServerConfig).Accounts = map[string]string{"foreign-user": "synthetic-password"}
			},
			"multiple-workers": func(h *AlwaysOnInboundHandler) { h.workers = append(h.workers, h.workers[0]) },
			"wrong-protocol":   func(h *AlwaysOnInboundHandler) { h.proxyConfig = &proxyman.ReceiverConfig{} },
		} {
			t.Run(name, func(t *testing.T) {
				ctx, key, h, owner, _ := nativeRoutingInboundFixture(t)
				change(h)
				if err := bindNativeRoutingInput(ctx, key, h); err == nil {
					t.Fatal("unqualified selected handler admitted")
				}
				if err := owner.Seal(core.FromContext(ctx)); err == nil {
					t.Fatal("failed candidate left a usable routing input")
				}
			})
		}
	})
}

func TestNativeRoutingInputOwnedControl(t *testing.T) {
	ctx, key, h, owner, p := nativeRoutingInboundFixture(t)
	conn := newNativeRoutingFakeConn()
	entered := make(chan struct{})
	ended := make(chan error, 1)
	var activeRoute context.Context
	processError := errors.New("synthetic proxy result")
	p.process = func(bound context.Context, n net.Network, actual stat.Connection, _ routing.Dispatcher) error {
		if n != net.Network_TCP || actual != conn || session.InboundFromContext(bound).Conn != conn {
			t.Error("wrapper changed actual control identity")
		}
		meta := routing.NativeRoutingMetadata{Conn: conn, Tag: "managed", Name: "socks", User: "private-user"}
		route, end, err := owner.BeginRoute(bound, core.FromContext(bound), meta)
		if err != nil {
			t.Error(err)
		} else {
			defer end()
			activeRoute = route
			if _, selected, err := owner.Decision(route, core.FromContext(bound), meta); err != nil || !selected {
				t.Error("control wrapper did not mint owned capsule")
			}
		}
		close(entered)
		_, _ = actual.Read(nil)
		return processError
	}
	var closes atomic.Int32
	p.close = func() error {
		closes.Add(1)
		meta := routing.NativeRoutingMetadata{Conn: conn, Tag: "managed", User: "private-user"}
		if _, selected, err := owner.Decision(activeRoute, core.FromContext(ctx), meta); err == nil || selected {
			t.Error("base proxy Close preceded synchronous policy revocation")
		}
		return nil
	}
	if err := bindNativeRoutingInput(ctx, key, h); err != nil {
		t.Fatal(err)
	}
	if h.proxy == p || h.workers[0].Proxy() != h.proxy {
		t.Fatal("selected handler/worker proxies not bound together")
	}
	if err := owner.Seal(core.FromContext(ctx)); err != nil {
		t.Fatal(err)
	}
	flowCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: "managed", Conn: conn})
	go func() { ended <- h.proxy.Process(flowCtx, net.Network_TCP, conn, nil) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("inert process was not entered")
	}
	if err := h.workers[0].Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		if err != processError {
			t.Fatal("original Process error replaced")
		}
	case <-time.After(time.Second):
		t.Fatal("revocation failed to close owned control")
	}
	_ = h.proxy.(interface{ Close() error }).Close()
	if closes.Load() != 1 || conn.count.Load() != 1 {
		t.Fatal("base proxy/control closed more than once")
	}
	if err := h.proxy.Process(flowCtx, net.Network_TCP, conn, nil); err == nil {
		t.Fatal("closed input readmitted control")
	}
}

func TestNativeRoutingInputRejectsBorrowedConnection(t *testing.T) {
	ctx, key, h, owner, p := nativeRoutingInboundFixture(t)
	var called bool
	p.process = func(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
		called = true
		return nil
	}
	if err := bindNativeRoutingInput(ctx, key, h); err != nil {
		t.Fatal(err)
	}
	if err := owner.Seal(core.FromContext(ctx)); err != nil {
		t.Fatal(err)
	}
	conn, foreign := newNativeRoutingFakeConn(), newNativeRoutingFakeConn()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "managed", Conn: foreign})
	if err := h.proxy.Process(ctx, net.Network_TCP, conn, nil); err == nil || called || conn.count.Load() != 0 || foreign.count.Load() != 0 {
		t.Fatal("borrowed metadata reached proxy or closed an unowned connection")
	}
}
