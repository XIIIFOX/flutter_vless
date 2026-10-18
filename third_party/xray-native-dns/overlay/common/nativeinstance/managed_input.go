package nativeinstance

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// ManagedInputPolicy appends one PRIVATE native input in the per-Start clone.
// It never selects/edits an imported input and creates no tag/routing rule or
// outbound. All admitted source/native TCP callbacks share a four-connection
// preview budget and are closed by the Runtime. Ordinary TCP delegates to caller routing; ordinary UDP is refused
// in this preview. Mux/XUDP through this managed input is deliberately denied.
// Credentials are trusted side metadata, never source JSON or diagnostics.
type ManagedInputPolicy struct {
	Listen             netip.AddrPort
	Username, Password string
}

const maxManagedInputFlows = 4

type managedInput struct {
	mu                sync.Mutex
	runtime           *Runtime
	config            *core.Config
	selected          *core.InboundHandlerConfig
	known             map[*core.InboundHandlerConfig]bool
	handlers          map[*core.InboundHandlerConfig]featureinbound.Handler
	instance          *core.Instance
	sealed, closed    bool
	slots             chan struct{}
	flows             map[*managedFlow]bool
	workers           sync.WaitGroup
	connections       map[*managedConnection]bool
	udpPeers          map[netip.AddrPort]*managedConnection
	connectionSlots   chan struct{}
	connectionWorkers sync.WaitGroup
}

func newManagedInput(r *Runtime, c *core.Config, index int) *managedInput {
	input := &managedInput{runtime: r, config: c, selected: c.Inbound[index], known: make(map[*core.InboundHandlerConfig]bool), handlers: make(map[*core.InboundHandlerConfig]featureinbound.Handler), slots: make(chan struct{}, maxManagedInputFlows), flows: make(map[*managedFlow]bool), connections: make(map[*managedConnection]bool), udpPeers: make(map[netip.AddrPort]*managedConnection), connectionSlots: make(chan struct{}, maxManagedInputFlows)}
	for _, key := range c.Inbound {
		input.known[key] = true
	}
	return input
}

func pointer(value any) bool {
	v := reflect.ValueOf(value)
	return v.IsValid() && v.Kind() == reflect.Pointer && !v.IsNil()
}

// BindInput is called only from the actual Core inbound constructor. The exact
// clone key, constructing Core and real handler are retained. Matching a tag or
// a freshly decoded equal proto cannot obtain the managed dispatcher.
func (input *managedInput) BindInput(ctx context.Context, instance, key, handler any, base routing.Dispatcher) (routing.Dispatcher, error) {
	coreInstance, ok := instance.(*core.Instance)
	if !ok || coreInstance == nil || core.FromContext(ctx) != coreInstance || base == nil || !pointer(handler) {
		return nil, routing.ErrNativeInput
	}
	config, ok := key.(*core.InboundHandlerConfig)
	if !ok || config == nil {
		return nil, routing.ErrNativeInput
	}
	actual, ok := handler.(featureinbound.Handler)
	if !ok || actual.Tag() != config.Tag {
		return nil, routing.ErrNativeInput
	}
	input.mu.Lock()
	defer input.mu.Unlock()
	if input.closed || input.sealed || !input.known[config] || input.handlers[config] != nil || input.runtime.life.Err() != nil ||
		input.instance != nil && input.instance != coreInstance {
		return nil, routing.ErrNativeInput
	}
	input.instance = coreInstance
	input.handlers[config] = actual
	if config != input.selected {
		return base, nil
	}
	return &managedDispatcher{input: input, key: config, handler: actual, instance: coreInstance, base: base}, nil
}

type inputSealer interface {
	SealNativeInputHandlers([]featureinbound.Handler) error
}

func (input *managedInput) seal(instance any, manager featureinbound.Manager) error {
	input.mu.Lock()
	defer input.mu.Unlock()
	if input.closed || input.sealed || instance != input.instance || manager == nil || !pointer(manager) || len(input.handlers) != len(input.known) {
		return routing.ErrNativeInput
	}
	sealer, ok := manager.(inputSealer)
	if !ok {
		return routing.ErrNativeInput
	}
	expected := make([]featureinbound.Handler, 0, len(input.handlers))
	for _, handler := range input.handlers {
		expected = append(expected, handler)
	}
	if sealer.SealNativeInputHandlers(expected) != nil || input.runtime.life.Err() != nil {
		return routing.ErrNativeInput
	}
	input.sealed = true
	return nil
}

func (input *managedInput) close() {
	input.mu.Lock()
	input.closed = true
	flows := make([]*managedFlow, 0, len(input.flows))
	for flow := range input.flows {
		flows = append(flows, flow)
	}
	connections := make([]*managedConnection, 0, len(input.connections))
	for connection := range input.connections {
		connections = append(connections, connection)
	}
	input.mu.Unlock()
	for _, connection := range connections {
		connection.close()
	}
	for _, flow := range flows {
		flow.close()
	}
	input.workers.Wait()
	input.connectionWorkers.Wait()
}

type managedConnectionKey struct{}
type ownedInputConnectionKey struct{}
type managedConnection struct {
	input                  *managedInput
	key                    *core.InboundHandlerConfig
	udpPeer                netip.AddrPort // guarded by input.mu; retained until Process finalizer
	ctx                    context.Context
	cancel                 context.CancelFunc
	conn                   net.Conn
	once                   sync.Once
	stopOwner, stopContext func() bool
}

func (c *managedConnection) close() { c.once.Do(func() { c.cancel(); _ = c.conn.Close() }) }

func (input *managedInput) BeginInput(ctx context.Context, instance, key, handler any, conn net.Conn) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || conn == nil {
		return nil, nil, routing.ErrNativeInput
	}
	config, ok := key.(*core.InboundHandlerConfig)
	if !ok {
		return nil, nil, routing.ErrNativeInput
	}
	input.mu.Lock()
	if input.closed || !input.sealed || instance != input.instance || core.FromContext(ctx) != input.instance || !input.known[config] || input.handlers[config] != handler || !input.runtime.current() {
		input.mu.Unlock()
		return nil, nil, routing.ErrNativeInput
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Conn != conn {
		input.mu.Unlock()
		return nil, nil, routing.ErrNativeInput
	}
	select {
	case input.connectionSlots <- struct{}{}:
	default:
		input.mu.Unlock()
		return nil, nil, ErrBusy
	}
	operation, cancel := context.WithCancel(ctx)
	connection := &managedConnection{input: input, key: config, ctx: operation, cancel: cancel, conn: conn}
	input.connections[connection] = true
	input.connectionWorkers.Add(1)
	input.mu.Unlock()
	connection.stopOwner = context.AfterFunc(input.runtime.life, cancel)
	connection.stopContext = context.AfterFunc(operation, connection.close)
	var finishOnce sync.Once
	end := func() {
		finishOnce.Do(func() {
			connection.stopOwner()
			connection.stopContext()
			connection.close()
			input.mu.Lock()
			if input.udpPeers[connection.udpPeer] == connection {
				delete(input.udpPeers, connection.udpPeer)
			}
			delete(input.connections, connection)
			input.mu.Unlock()
			<-input.connectionSlots
			input.connectionWorkers.Done()
		})
	}
	operation = context.WithValue(operation, ownedInputConnectionKey{}, connection)
	if config == input.selected {
		operation = context.WithValue(operation, managedConnectionKey{}, connection)
	}
	return operation, end, nil
}

// Called after SOCKS password authentication, before allocating its UDP hub.
// Neither a tag nor the first UDP datagram may choose the private peer. Revoke
// closes sockets immediately; tuple reuse waits for the whole SOCKS finalizer.
func (input *managedInput) AuthorizeUDPAssociation(ctx context.Context, peer netip.AddrPort) error {
	if ctx == nil || ctx.Err() != nil {
		return routing.ErrNativeInput
	}
	connection, _ := ctx.Value(ownedInputConnectionKey{}).(*managedConnection)
	inbound := session.InboundFromContext(ctx)
	input.mu.Lock()
	defer input.mu.Unlock()
	if connection == nil || connection.input != input || !input.connections[connection] || connection.ctx.Err() != nil ||
		inbound == nil || inbound.Conn != connection.conn || input.closed || !input.sealed ||
		core.FromContext(ctx) != input.instance || !input.runtime.current() || !input.known[connection.key] {
		return routing.ErrNativeInput
	}
	if connection.key != input.selected {
		return nil // exact, construction-owned imported input keeps Core semantics
	}
	private, _ := ctx.Value(managedConnectionKey{}).(*managedConnection)
	remote, ok := connection.conn.RemoteAddr().(*net.TCPAddr)
	if private != connection || !ok || remote == nil || !remote.IP.Equal(net.IPv4(127, 0, 0, 1)) ||
		!peer.IsValid() || peer.Addr() != netip.MustParseAddr("127.0.0.1") || peer.Port() == 0 ||
		connection.udpPeer.IsValid() || input.udpPeers[peer] != nil {
		return routing.ErrNativeInput
	}
	connection.udpPeer = peer
	input.udpPeers[peer] = connection
	return nil
}

type managedDispatcher struct {
	input    *managedInput
	key      *core.InboundHandlerConfig
	handler  featureinbound.Handler
	instance *core.Instance
	base     routing.Dispatcher
}

func (d *managedDispatcher) Type() any    { return routing.DispatcherType() }
func (d *managedDispatcher) Start() error { return nil }
func (d *managedDispatcher) Close() error { return nil } // owning Runtime closes input

func (d *managedDispatcher) authorized(ctx context.Context) bool {
	input := d.input
	if input == nil || input.runtime == nil || input.runtime.input != input || input.runtime.bridge == nil || input.runtime.bridge.identity != input.config {
		return false
	}
	connection, _ := ctx.Value(managedConnectionKey{}).(*managedConnection)
	inbound := session.InboundFromContext(ctx)
	return connection != nil && connection.key == input.selected && inbound != nil && inbound.Conn == connection.conn && connection.input == input && input.connections[connection] && connection.ctx.Err() == nil &&
		input != nil && input.runtime != nil && input.sealed && !input.closed && input.selected == d.key &&
		input.handlers[d.key] == d.handler && input.instance == d.instance && core.FromContext(ctx) == d.instance && input.runtime.current()
}

func (d *managedDispatcher) acquire(ctx context.Context, link *transport.Link, udp bool) (*managedFlow, error) {
	if ctx == nil || ctx.Err() != nil || link == nil || link.Reader == nil || link.Writer == nil {
		return nil, routing.ErrNativeInput
	}
	inbound := session.InboundFromContext(ctx)
	// The real tcpWorker publishes this Conn before SOCKS authentication. Its
	// dispatcher is reached only after a successful password handshake. Keeping
	// the actual owned control socket makes cancellation unblock nonowning buf
	// wrappers as well as a SOCKS UDP Associate's temporary listener.
	if inbound == nil || inbound.Conn == nil {
		return nil, routing.ErrNativeInput
	}
	input := d.input
	input.mu.Lock()
	if !d.authorized(ctx) {
		input.mu.Unlock()
		return nil, routing.ErrNativeInput
	}
	connection, _ := ctx.Value(managedConnectionKey{}).(*managedConnection)
	if udp && (!connection.udpPeer.IsValid() || input.udpPeers[connection.udpPeer] != connection) {
		input.mu.Unlock()
		return nil, routing.ErrNativeInput
	}
	select {
	case input.slots <- struct{}{}:
	default:
		input.mu.Unlock()
		return nil, ErrBusy
	}
	operation, cancel := context.WithCancel(ctx)
	flow := &managedFlow{input: input, ctx: operation, cancel: cancel, link: link, conn: inbound.Conn}
	input.flows[flow] = true
	input.workers.Add(1)
	input.mu.Unlock()
	flow.stopOwner = context.AfterFunc(input.runtime.life, cancel)
	flow.stopContext = context.AfterFunc(operation, flow.close)
	return flow, nil
}

// Dispatch is used by SOCKS UDP. Core's UDP dispatcher caches ONE ray, so every
// managed UDP ray must remain a demultiplexer even if its first packet is not
// DNS. Each Buffer.UDP is validated; first-destination classification is unsafe.
func (d *managedDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	if !destination.IsValid() || destination.Address == nil || destination.Address.String() == "v1.mux.cool" {
		return nil, routing.ErrNativeInput
	}
	options := pipe.OptionsFromContext(ctx)
	upReader, upWriter := pipe.New(options...)
	downReader, downWriter := pipe.New(options...)
	service := &transport.Link{Reader: upReader, Writer: downWriter}
	flow, err := d.acquire(ctx, service, destination.Network == xnet.Network_UDP)
	if err != nil {
		common.Interrupt(upReader)
		common.Interrupt(upWriter)
		common.Interrupt(downReader)
		common.Interrupt(downWriter)
		return nil, err
	}
	// The bounded flow slot is reserved BEFORE adding a worker goroutine.
	go func() { defer flow.finish(); _ = d.process(flow, destination) }()
	return &transport.Link{Reader: downReader, Writer: upWriter}, nil
}
func (d *managedDispatcher) DispatchLink(ctx context.Context, destination xnet.Destination, link *transport.Link) error {
	if !destination.IsValid() || destination.Address == nil || destination.Address.String() == "v1.mux.cool" {
		return routing.ErrNativeInput
	}
	flow, err := d.acquire(ctx, link, destination.Network == xnet.Network_UDP)
	if err != nil {
		return err
	}
	defer flow.finish()
	return d.process(flow, destination)
}
func (d *managedDispatcher) process(flow *managedFlow, destination xnet.Destination) error {
	if destination.Network == xnet.Network_UDP {
		return d.processUDP(flow)
	}
	if destination.Network != xnet.Network_TCP {
		return routing.ErrNativeInput
	}
	bridge := &SystemDNSBridge{runtime: d.input.runtime, binding: d.input.runtime.bridge}
	if !bridgeTarget(d.input.runtime.bridge, destination) {
		return d.base.DispatchLink(flow.ctx, destination, flow.link)
	}
	// Own the framing buffer explicitly. The pinned generic TCPReader leaks
	// its newly pooled message on truncated body and does not release cached
	// pipelined input on Close; this bounded native path must not inherit that.
	reader := &buf.BufferedReader{Reader: managedFramingReader{flow.link.Reader}}
	defer func() { buf.ReleaseMulti(reader.Buffer); reader.Buffer = nil }()
	for {
		var size [2]byte
		n, err := io.ReadFull(reader, size[:])
		if err != nil {
			if n == 0 && errors.Is(err, io.EOF) {
				return nil
			}
			return ErrDNSQuery
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length < 12 || length > maxSystemDNSQuery {
			return ErrDNSQuery
		}
		packet := make([]byte, length+2)
		copy(packet, size[:])
		if _, err := io.ReadFull(reader, packet[2:]); err != nil {
			return ErrDNSQuery
		}
		response, err := bridge.ExchangeTCP(flow.ctx, netip.AddrPortFrom(d.input.runtime.bridge.virtual, 53), packet)
		if err != nil {
			return err
		}
		if err := flow.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(response)}); err != nil {
			return ErrDNSQuery
		}
	}
}

// BufferedReader drops a MultiBuffer paired with an error before caching it.
// Own that terminal data at the adapter boundary, never leaking it into the
// generic reader. It is deliberately not a partial-DNS success path.
type managedFramingReader struct{ buf.Reader }

func (r managedFramingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packets, err := r.Reader.ReadMultiBuffer()
	if err != nil {
		buf.ReleaseMulti(packets)
		return nil, err
	}
	return packets, nil
}

func bridgeTarget(binding *systemDNSBinding, destination xnet.Destination) bool {
	return binding != nil && destination.Address != nil && destination.Address.Family().IsIPv4() && destination.Port == 53 && destination.Address.IP().String() == binding.virtual.String()
}
func (d *managedDispatcher) processUDP(flow *managedFlow) error {
	bridge := &SystemDNSBridge{runtime: d.input.runtime, binding: d.input.runtime.bridge}
	for {
		packets, err := flow.link.Reader.ReadMultiBuffer()
		if err != nil {
			// A Reader may return owned data together with its terminal error.
			// Refusal still owns that data and must release it before returning.
			buf.ReleaseMulti(packets)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return ErrDNSQuery
		}
		for index, packet := range packets {
			// Ordinary UDP is explicitly pending. Never fall through to a raw relay,
			// even when a non-DNS first packet created this cached association ray.
			if packet.UDP == nil || !bridgeTarget(d.input.runtime.bridge, *packet.UDP) || packet.UDP.Network != xnet.Network_UDP {
				packet.Release()
				continue
			}
			response, queryErr := bridge.ExchangeUDP(flow.ctx, netip.AddrPortFrom(d.input.runtime.bridge.virtual, 53), packet.Bytes())
			packet.Release()
			if queryErr != nil {
				if flow.ctx.Err() != nil {
					buf.ReleaseMulti(packets[index+1:])
					return ErrClosed
				}
				continue
			}
			output := buf.FromBytes(response)
			target := xnet.UDPDestination(xnet.ParseAddress(d.input.runtime.bridge.virtual.String()), 53)
			output.UDP = &target
			if flow.link.Writer.WriteMultiBuffer(buf.MultiBuffer{output}) != nil {
				buf.ReleaseMulti(packets[index+1:])
				return ErrDNSQuery
			}
		}
	}
}

type managedFlow struct {
	input                  *managedInput
	ctx                    context.Context
	cancel                 context.CancelFunc
	link                   *transport.Link
	conn                   net.Conn
	closeOnce              sync.Once
	stopOwner, stopContext func() bool
}

func (f *managedFlow) close() {
	f.closeOnce.Do(func() {
		f.cancel()
		common.Interrupt(f.link.Reader)
		common.Interrupt(f.link.Writer)
		_ = f.conn.Close()
	})
}
func (f *managedFlow) finish() {
	f.stopOwner()
	f.stopContext()
	f.close()
	f.input.mu.Lock()
	delete(f.input.flows, f)
	f.input.mu.Unlock()
	<-f.input.slots
	f.input.workers.Done()
}
