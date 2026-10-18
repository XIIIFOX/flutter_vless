package nativeinstance

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type fakeNativeHandler struct{ tag string }

func (*fakeNativeHandler) Start() error                                 { return nil }
func (*fakeNativeHandler) Close() error                                 { return nil }
func (h *fakeNativeHandler) Tag() string                                { return h.tag }
func (*fakeNativeHandler) ReceiverSettings() *commonserial.TypedMessage { return nil }
func (*fakeNativeHandler) ProxySettings() *commonserial.TypedMessage    { return nil }

type fakeNativeManager struct {
	handlers []featureinbound.Handler
	sealed   bool
}

func (*fakeNativeManager) Type() any    { return featureinbound.ManagerType() }
func (*fakeNativeManager) Start() error { return nil }
func (*fakeNativeManager) Close() error { return nil }
func (m *fakeNativeManager) GetHandler(context.Context, string) (featureinbound.Handler, error) {
	return nil, ErrClosed
}
func (m *fakeNativeManager) AddHandler(context.Context, featureinbound.Handler) error {
	return ErrClosed
}
func (m *fakeNativeManager) RemoveHandler(context.Context, string) error           { return ErrClosed }
func (m *fakeNativeManager) ListHandlers(context.Context) []featureinbound.Handler { return m.handlers }
func (m *fakeNativeManager) SealNativeInputHandlers(h []featureinbound.Handler) error {
	if m.sealed || len(h) != len(m.handlers) {
		return ErrClosed
	}
	expected := map[featureinbound.Handler]bool{}
	for _, x := range h {
		expected[x] = true
	}
	for _, x := range m.handlers {
		if !expected[x] {
			return ErrClosed
		}
	}
	m.sealed = true
	return nil
}

type fakeInputCore struct {
	*fakeCore
	identity *core.Instance
	manager  *fakeNativeManager
}

func (f *fakeInputCore) nativeInputIdentity() any                   { return f.identity }
func (f *fakeInputCore) nativeInputManager() featureinbound.Manager { return f.manager }

type fakeOrdinaryDispatcher struct{ calls atomic.Int32 }

func (*fakeOrdinaryDispatcher) Type() any    { return routing.DispatcherType() }
func (*fakeOrdinaryDispatcher) Start() error { return nil }
func (*fakeOrdinaryDispatcher) Close() error { return nil }
func (*fakeOrdinaryDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, ErrUnsupported
}
func (d *fakeOrdinaryDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	d.calls.Add(1)
	return nil
}

type fakeManagedConn struct {
	once   sync.Once
	closed chan struct{}
	closes atomic.Int32
}

func newFakeManagedConn() *fakeManagedConn             { return &fakeManagedConn{closed: make(chan struct{})} }
func (c *fakeManagedConn) Read([]byte) (int, error)    { <-c.closed; return 0, io.EOF }
func (c *fakeManagedConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakeManagedConn) Close() error {
	c.once.Do(func() { c.closes.Add(1); close(c.closed) })
	return nil
}
func (*fakeManagedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
}
func (*fakeManagedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 23456}
}
func (*fakeManagedConn) SetDeadline(time.Time) error      { return nil }
func (*fakeManagedConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeManagedConn) SetWriteDeadline(time.Time) error { return nil }
func managedPolicy() Policy {
	p := bridgePolicy()
	p.LookupTimeout = time.Second
	p.ManagedInput = &ManagedInputPolicy{Listen: netip.MustParseAddrPort("127.0.0.1:12346"), Username: "native-user", Password: "native-password"}
	return p
}
func managedRuntime(t *testing.T, f *fakeCore) (*Runtime, *managedDispatcher, *fakeOrdinaryDispatcher, context.Context) {
	t.Helper()
	p, err := PrepareJSON(testSource(), managedPolicy())
	if err != nil {
		t.Fatal(err)
	}
	base := &fakeOrdinaryDispatcher{}
	identity := &core.Instance{}
	manager := &fakeNativeManager{}
	var selected *managedDispatcher
	var constructorCtx context.Context
	r, err := p.start(context.Background(), func(ctx context.Context, c *core.Config) (runtimeCore, error) {
		factory, present := routing.NativeInputFactoryFromContext(ctx)
		if !present || factory == nil {
			t.Fatal("factory not supplied before Core constructor")
		}
		constructorCtx = context.WithValue(ctx, core.XrayKey(1), identity)
		for _, key := range c.Inbound {
			handler := &fakeNativeHandler{tag: key.Tag}
			manager.handlers = append(manager.handlers, handler)
			wrapped, err := factory.BindInput(constructorCtx, identity, key, handler, base)
			if err != nil {
				t.Fatal(err)
			}
			if view, ok := wrapped.(*managedDispatcher); ok {
				selected = view
			}
		}
		return &fakeInputCore{f, identity, manager}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeRuntime(t, r) })
	if selected == nil || !manager.sealed {
		t.Fatal("exact managed input was not bound/sealed")
	}
	return r, selected, base, constructorCtx
}
func managedContext(parent context.Context, conn *fakeManagedConn) context.Context {
	ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: conn, Gateway: xnet.TCPDestination(xnet.LocalHostIP, 12346)})
	factory, _ := routing.NativeInputFactoryFromContext(parent)
	input := factory.(*managedInput)
	operation, end, err := input.BeginInput(ctx, input.instance, input.selected, input.handlers[input.selected], conn)
	if err != nil {
		panic("controlled native connection admission failed")
	}
	// A controlled pure callback ends when its owner/caller context is cancelled.
	// Actual Core wiring defers end until socks.Process has completed UDP cleanup.
	context.AfterFunc(operation, end)
	return operation
}

func readManagedPacket(t *testing.T, link *transport.Link) *buf.Buffer {
	t.Helper()
	reader, ok := link.Reader.(buf.TimeoutReader)
	if !ok {
		t.Fatal("fixture reader not bounded")
	}
	packets, err := reader.ReadMultiBufferTimeout(time.Second)
	if err != nil || len(packets) != 1 {
		buf.ReleaseMulti(packets)
		t.Fatal("expected bounded managed packet", err)
	}
	return packets[0]
}
func writeManagedPacket(t *testing.T, link *transport.Link, packet []byte, destination *xnet.Destination) {
	t.Helper()
	b := buf.FromBytes(packet)
	b.UDP = destination
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeManagedInputPolicyAndPrivateClone(t *testing.T) {
	policy := managedPolicy()
	p, err := PrepareJSON(testSource(), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.ManagedInput.Password = "mutated"
	policy.ManagedInput.Listen = netip.MustParseAddrPort("127.0.0.1:12399")
	c, _, err := p.clone()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Inbound) != len(p.blueprint.Inbound)+1 {
		t.Fatal("native input not appended exactly once")
	}
	for i, key := range p.blueprint.Inbound {
		if !proto.Equal(key, c.Inbound[i]) {
			t.Fatal("caller input changed")
		}
	}
	for i, key := range p.blueprint.Outbound {
		if !proto.Equal(key, c.Outbound[i]) {
			t.Fatal("caller output changed")
		}
	}
	if !proto.Equal(dnsFeature(t, c), dnsFeature(t, p.blueprint)) {
		t.Fatal("caller DNS changed")
	}
	native := c.Inbound[len(c.Inbound)-1]
	settings, _ := native.ProxySettings.GetInstance()
	receiver, _ := native.ReceiverSettings.GetInstance()
	s := settings.(*socks.ServerConfig)
	r := receiver.(*proxyman.ReceiverConfig)
	if native.Tag != "" || !s.UdpEnabled || s.AuthType != socks.AuthType_PASSWORD || s.Accounts["native-user"] != "native-password" || r.PortList.Range[0].From != 12346 {
		t.Fatal("native policy copy/binding changed")
	}
	for name, mutate := range map[string]func(*Policy){"noengine": func(p *Policy) { p.SystemDNSBridge = nil }, "listen": func(p *Policy) { p.ManagedInput.Listen = netip.MustParseAddrPort("0.0.0.0:53") }, "emptyauth": func(p *Policy) { p.ManagedInput.Password = "" }, "overlap": func(p *Policy) { p.ManagedInput.Listen = netip.MustParseAddrPort("127.0.0.1:12345") }} {
		t.Run(name, func(t *testing.T) {
			p := managedPolicy()
			mutate(&p)
			if _, err := PrepareJSON(testSource(), p); !errors.Is(err, ErrPolicy) {
				t.Fatal("invalid managed policy accepted")
			}
		})
	}
}

func TestNativeManagedInputUDPChecksEveryPayloadMetadata(t *testing.T) {
	f := &fakeCore{}
	_, dispatcher, base, parent := managedRuntime(t, f)
	conn := newFakeManagedConn()
	ctx, cancel := context.WithTimeout(managedContext(parent, conn), time.Second)
	defer cancel()
	ordinary := xnet.UDPDestination(xnet.LocalHostIP, 9999)
	virtual := xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)
	link, err := dispatcher.Dispatch(ctx, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	query := bridgeQuery(t, dnsmessage.TypeA)
	// The first ordinary datagram creates the cached ray. A later DNS packet
	// MUST still reach the engine; the following ordinary/missing-context packet
	// MUST NOT be interpreted as DNS just because the ray now carried DNS.
	writeManagedPacket(t, link, query, &ordinary)
	writeManagedPacket(t, link, query, &virtual)
	answer := readManagedPacket(t, link)
	if answer.UDP == nil || !bridgeTarget(dispatcher.input.runtime.bridge, *answer.UDP) {
		t.Fatal("response endpoint metadata lost")
	}
	_ = bridgeResponse(t, answer.Bytes(), false)
	answer.Release()
	writeManagedPacket(t, link, query, &ordinary)
	writeManagedPacket(t, link, query, nil)
	writeManagedPacket(t, link, query, &virtual)
	answer = readManagedPacket(t, link)
	_ = bridgeResponse(t, answer.Bytes(), false)
	answer.Release()
	if f.queries.Load() != 2 || base.calls.Load() != 0 {
		t.Fatal("per-packet UDP refusal/bridge selection failed")
	}
	cancel()
	await(t, conn.closed)
}

func TestNativeManagedInputOwnedFlowBoundBeforeSpawnAndCancel(t *testing.T) {
	r, dispatcher, _, parent := managedRuntime(t, &fakeCore{})
	destination := xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)
	conn := newFakeManagedConn()
	ctx := managedContext(parent, conn)
	for i := 0; i < maxManagedInputFlows; i++ {
		if _, err := dispatcher.Dispatch(ctx, destination); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dispatcher.Dispatch(ctx, destination); !errors.Is(err, ErrBusy) {
		t.Fatal("flow bound did not refuse before goroutine")
	}
	r.input.mu.Lock()
	count := len(r.input.flows)
	r.input.mu.Unlock()
	if count != maxManagedInputFlows {
		t.Fatal("unexpected owned flow count")
	}
	closeRuntime(t, r)
	await(t, conn.closed)
	if conn.closes.Load() != 1 {
		t.Fatal("owned connection closed repeatedly")
	}
	if _, err := dispatcher.Dispatch(session.ContextWithInbound(parent, &session.Inbound{Conn: newFakeManagedConn()}), destination); err == nil {
		t.Fatal("stale dispatcher admitted after Close")
	}
}

func TestNativeManagedInputOrdinaryTCPDelegatesAndMuxDenied(t *testing.T) {
	_, dispatcher, base, parent := managedRuntime(t, &fakeCore{})
	destination := xnet.TCPDestination(xnet.LocalHostIP, 8080)
	conn := newFakeManagedConn()
	// No reader is used by the fake ordinary delegate; the actual dispatch path
	// still owns the precise TCP control socket and closes it on completion.
	link, err := dispatcher.Dispatch(managedContext(parent, conn), destination)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(time.Second)
	await(t, conn.closed)
	if base.calls.Load() != 1 {
		t.Fatal("ordinary TCP routing did not delegate")
	}
	if _, err := dispatcher.Dispatch(managedContext(parent, newFakeManagedConn()), xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), 9527)); err == nil {
		t.Fatal("managed mux/XUDP admitted")
	}
}

func TestNativeManagedInputForeignContextAndConfigCannotAuthorize(t *testing.T) {
	_, dispatcher, base, parent := managedRuntime(t, &fakeCore{})
	destination := xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)
	foreign := context.WithValue(parent, core.XrayKey(1), &core.Instance{})
	for _, ctx := range []context.Context{context.Background(), foreign, parent} {
		if _, err := dispatcher.Dispatch(ctx, destination); err == nil {
			t.Fatal("missing/foreign owned connection context admitted")
		}
	}
	equalCopy := proto.Clone(dispatcher.key).(*core.InboundHandlerConfig)
	if _, err := dispatcher.input.BindInput(parent, dispatcher.instance, equalCopy, &fakeNativeHandler{}, base); err == nil {
		t.Fatal("equal detached compiled key admitted")
	}
}

type managedRetainedReader struct {
	packet *buf.Buffer
	read   bool
	err    error
}

func (r *managedRetainedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.read {
		return nil, io.EOF
	}
	r.read = true
	return buf.MultiBuffer{r.packet}, r.err
}

type managedTestWriter struct {
	fail   bool
	writes int
}

func (w *managedTestWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	w.writes++
	if w.fail {
		return errors.New("fixed writer failure")
	}
	return nil
}
func TestNativeManagedInputFramingOwnsPartialAndPipelinedBuffers(t *testing.T) {
	for _, kind := range []string{"partial-body", "oversized-length", "pipelined-write-error", "data-plus-EOF", "data-plus-error"} {
		t.Run(kind, func(t *testing.T) {
			f := &fakeCore{}
			_, dispatcher, _, parent := managedRuntime(t, f)
			packet := buf.New()
			writer := &managedTestWriter{}
			switch kind {
			case "partial-body":
				_, _ = packet.Write([]byte{0, 20, 1, 2, 3})
			case "oversized-length":
				_, _ = packet.Write([]byte{2, 1, 9, 9, 9})
			case "pipelined-write-error":
				wire := bridgeFrame(bridgeQuery(t, dnsmessage.TypeA))
				_, _ = packet.Write(wire)
				_, _ = packet.Write(wire)
				writer.fail = true
			}
			reader := &managedRetainedReader{packet: packet}
			if kind == "data-plus-EOF" || kind == "data-plus-error" {
				_, _ = packet.Write(bridgeFrame(bridgeQuery(t, dnsmessage.TypeA)))
				reader.err = io.EOF
				if kind == "data-plus-error" {
					reader.err = errors.New("fixed terminal stream failure")
				}
			}
			conn := newFakeManagedConn()
			err := dispatcher.DispatchLink(managedContext(parent, conn), xnet.TCPDestination(xnet.ParseAddress("198.18.0.53"), 53), &transport.Link{Reader: reader, Writer: writer})
			if kind != "data-plus-EOF" && err == nil || packet.Len() != 0 {
				t.Fatal("malformed/failed stream retained a pooled input buffer")
			}
			if kind != "pipelined-write-error" && f.queries.Load() != 0 {
				t.Fatal("invalid frame entered DNS")
			}
			if kind == "pipelined-write-error" && (f.queries.Load() != 1 || writer.writes != 1) {
				t.Fatal("pipeline did not stop at failed publication")
			}
		})
	}
}
func TestNativeManagedInputCloseWaitsWholeSOCKSCallback(t *testing.T) {
	r, _, _, parent := managedRuntime(t, &fakeCore{})
	conn := newFakeManagedConn()
	ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: conn})
	operation, end, err := r.input.BeginInput(ctx, r.input.instance, r.input.selected, r.input.handlers[r.input.selected], conn)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if !errors.Is(r.Close(wait), ErrDrain) {
		t.Fatal("Close ignored outstanding SOCKS callback finalizer")
	}
	await(t, conn.closed)
	await(t, operation.Done())
	end()
	closeRuntime(t, r)
}
func TestNativeManagedInputConnectionAdmissionBound(t *testing.T) {
	r, _, _, parent := managedRuntime(t, &fakeCore{})
	for i := 0; i < maxManagedInputFlows; i++ {
		conn := newFakeManagedConn()
		ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: conn})
		operation, end, err := r.input.BeginInput(ctx, r.input.instance, r.input.selected, r.input.handlers[r.input.selected], conn)
		if err != nil {
			t.Fatal(err)
		}
		context.AfterFunc(operation, end)
	}
	extra := newFakeManagedConn()
	ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: extra})
	if _, _, err := r.input.BeginInput(ctx, r.input.instance, r.input.selected, r.input.handlers[r.input.selected], extra); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded native authentication callback admission")
	}
	closeRuntime(t, r)
}

func TestNativeManagedInputOwnsImportedCallbackWithoutGrantingCapability(t *testing.T) {
	r, dispatcher, _, parent := managedRuntime(t, &fakeCore{})
	var source *core.InboundHandlerConfig
	for candidate := range r.input.known {
		if candidate != r.input.selected {
			source = candidate
			break
		}
	}
	if source == nil {
		t.Fatal("controlled imported input missing")
	}
	conn := newFakeManagedConn()
	ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: conn})
	operation, end, err := r.input.BeginInput(ctx, r.input.instance, source, r.input.handlers[source], conn)
	if err != nil {
		t.Fatal("construction-bound source callback refused", err)
	}
	defer end()
	if operation.Value(managedConnectionKey{}) != nil {
		t.Fatal("imported callback acquired DNS capability")
	}
	if _, err := dispatcher.Dispatch(operation, xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)); err == nil {
		t.Fatal("imported callback reached private dispatcher")
	}
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if !errors.Is(r.Close(wait), ErrDrain) {
		t.Fatal("Close ignored imported source callback finalizer")
	}
	await(t, conn.closed)
	await(t, operation.Done())
	end()
	closeRuntime(t, r)
}

func TestNativeManagedInputConnectionCapsuleCannotReplaceControlSocket(t *testing.T) {
	_, dispatcher, _, parent := managedRuntime(t, &fakeCore{})
	conn := newFakeManagedConn()
	ctx := managedContext(parent, conn)
	destination := xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)
	replacement := newFakeManagedConn()
	borrowed := session.ContextWithInbound(ctx, &session.Inbound{Conn: replacement})
	if _, err := dispatcher.Dispatch(borrowed, destination); !errors.Is(err, routing.ErrNativeInput) {
		t.Fatal("private capsule admitted a substituted control socket")
	}
	if replacement.closes.Load() != 0 || conn.closes.Load() != 0 {
		t.Fatal("rejected context closed a socket it did not acquire")
	}
	// Pinned SOCKS UDP creates a fresh Inbound value while retaining the exact
	// authenticated control connection. That legitimate copy remains admitted.
	copied := *session.InboundFromContext(ctx)
	link, err := dispatcher.Dispatch(session.ContextWithInbound(ctx, &copied), destination)
	if err != nil {
		t.Fatal("legitimate copied SOCKS session was refused", err)
	}
	commonInterruptLink(link)
}

func commonInterruptLink(link *transport.Link) {
	if reader, ok := link.Reader.(interface{ Interrupt() }); ok {
		reader.Interrupt()
	}
	if writer, ok := link.Writer.(interface{ Interrupt() }); ok {
		writer.Interrupt()
	}
}

func TestNativeManagedInputUDPReleasesDataReturnedWithError(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("fixed reader failure")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			f := &fakeCore{}
			_, dispatcher, _, parent := managedRuntime(t, f)
			packet := buf.New()
			_, _ = packet.Write(bridgeQuery(t, dnsmessage.TypeA))
			destination := xnet.UDPDestination(xnet.ParseAddress("198.18.0.53"), 53)
			packet.UDP = &destination
			reader := &managedRetainedReader{packet: packet, err: terminal}
			err := dispatcher.DispatchLink(managedContext(parent, newFakeManagedConn()), destination, &transport.Link{Reader: reader, Writer: &managedTestWriter{}})
			if !errors.Is(terminal, io.EOF) && !errors.Is(err, ErrDNSQuery) {
				t.Fatal("reader failure was masked")
			}
			if packet.Len() != 0 || packet.UDP != nil || f.queries.Load() != 0 {
				t.Fatal("terminal reader data was leaked or entered DNS")
			}
		})
	}
}
