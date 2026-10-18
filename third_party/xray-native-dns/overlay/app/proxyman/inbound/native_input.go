package inbound

import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Called before the handler can be added or started. Only the strict preview's
// single-port TCP SOCKS graph has qualified this worker hook. Its SOCKS UDP
// Associate still uses the same wrapped dispatcher for every UDP payload ray.
func configureNativeInput(ctx context.Context, key *core.InboundHandlerConfig, handler *AlwaysOnInboundHandler) error {
	factory, present := routing.NativeInputFactoryFromContext(ctx)
	if !present {
		return nil
	}
	if factory == nil || handler == nil || len(handler.workers) != 1 {
		return routing.ErrNativeInput
	}
	worker, ok := handler.workers[0].(*tcpWorker)
	if !ok {
		return routing.ErrNativeInput
	}
	replacement, err := factory.BindInput(ctx, core.MustFromContext(ctx), key, handler, worker.dispatcher)
	if err != nil || replacement == nil {
		return routing.ErrNativeInput
	}
	worker.dispatcher = replacement
	wrapped := &nativeInputProxy{base: handler.proxy, factory: factory, instance: core.MustFromContext(ctx), key: key, handler: handler}
	worker.proxy = wrapped
	handler.proxy = wrapped
	return nil
}

// Membership and later Add/Remove admission share the same manager mutex.
// No tag lookup followed by dispatch is used as an identity/lifetime boundary.
func (m *Manager) SealNativeInputHandlers(expected []featureinbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.nativeInputSealed || m.running || len(expected) != len(m.taggedHandlers)+len(m.untaggedHandlers) {
		return routing.ErrNativeInput
	}
	seen := make(map[featureinbound.Handler]bool, len(expected))
	for _, handler := range expected {
		identity := reflect.ValueOf(handler)
		if !identity.IsValid() || identity.Kind() != reflect.Pointer || identity.IsNil() || seen[handler] {
			return routing.ErrNativeInput
		}
		seen[handler] = true
	}
	for _, handler := range m.taggedHandlers {
		if !seen[handler] {
			return routing.ErrNativeInput
		}
	}
	for _, handler := range m.untaggedHandlers {
		if !seen[handler] {
			return routing.ErrNativeInput
		}
	}
	m.nativeInputSealed = true
	return nil
}

// Track the complete authenticated SOCKS callback, not only its DNS ray: UDP
// Associate closes its temporary listener only when this Process returns.
type nativeInputProxy struct {
	base     proxy.Inbound
	factory  routing.NativeInputFactory
	instance *core.Instance
	key      *core.InboundHandlerConfig
	handler  *AlwaysOnInboundHandler
}

func (p *nativeInputProxy) Network() []net.Network { return p.base.Network() }
func (p *nativeInputProxy) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	operation, end, err := p.factory.BeginInput(ctx, p.instance, p.key, p.handler, conn)
	if err != nil || operation == nil || end == nil {
		return routing.ErrNativeInput
	}
	defer end()
	return p.base.Process(operation, network, conn, dispatcher)
}
func (p *nativeInputProxy) Close() error { return common.Close(p.base) }
