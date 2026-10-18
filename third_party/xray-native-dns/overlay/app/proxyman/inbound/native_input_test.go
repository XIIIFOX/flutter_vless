package inbound

import (
	"context"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type pureNativeInputHandler struct {
	tag    string
	closes atomic.Int32
}

func (*pureNativeInputHandler) Start() error                           { return nil }
func (h *pureNativeInputHandler) Close() error                         { h.closes.Add(1); return nil }
func (h *pureNativeInputHandler) Tag() string                          { return h.tag }
func (*pureNativeInputHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (*pureNativeInputHandler) ProxySettings() *serial.TypedMessage    { return nil }
func TestNativeInputManagerSealUsesPointerMembershipAndDeniesMutation(t *testing.T) {
	manager := &Manager{taggedHandlers: make(map[string]featureinbound.Handler)}
	a, b := &pureNativeInputHandler{}, &pureNativeInputHandler{tag: "caller-tag"}
	if manager.AddHandler(context.Background(), a) != nil || manager.AddHandler(context.Background(), b) != nil {
		t.Fatal("pure construction failed")
	}
	equalTag := &pureNativeInputHandler{tag: "caller-tag"}
	if manager.SealNativeInputHandlers([]featureinbound.Handler{a, equalTag}) == nil {
		t.Fatal("tag substituted actual handler identity")
	}
	if manager.SealNativeInputHandlers([]featureinbound.Handler{a, a}) == nil {
		t.Fatal("duplicate handler pointer accepted")
	}
	if manager.SealNativeInputHandlers([]featureinbound.Handler{b, a}) != nil {
		t.Fatal("exact tagged/untagged membership refused")
	}
	if manager.AddHandler(context.Background(), &pureNativeInputHandler{}) == nil || manager.RemoveHandler(context.Background(), b.Tag()) == nil {
		t.Fatal("sealed hot mutation admitted")
	}
	if b.closes.Load() != 0 || len(manager.ListHandlers(context.Background())) != 2 {
		t.Fatal("rejected mutation changed active membership")
	}
}
func TestNativeInputManagerLegacyNotSealed(t *testing.T) {
	manager := &Manager{taggedHandlers: make(map[string]featureinbound.Handler)}
	handler := &pureNativeInputHandler{tag: "legacy"}
	if manager.AddHandler(context.Background(), handler) != nil || manager.RemoveHandler(context.Background(), handler.Tag()) != nil || handler.closes.Load() != 1 {
		t.Fatal("legacy manager mutation behavior changed")
	}
}

type pureNativeCallbackFactory struct{ ended chan struct{} }

func (*pureNativeCallbackFactory) BindInput(context.Context, any, any, any, routing.Dispatcher) (routing.Dispatcher, error) {
	return nil, routing.ErrNativeInput
}
func (f *pureNativeCallbackFactory) BeginInput(ctx context.Context, _ any, _ any, _ any, _ gonet.Conn) (context.Context, func(), error) {
	return ctx, func() { close(f.ended) }, nil
}

type pureNativeCallbackProxy struct{ entered, release chan struct{} }

func (*pureNativeCallbackProxy) Network() []net.Network { return []net.Network{net.Network_TCP} }
func (p *pureNativeCallbackProxy) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	close(p.entered)
	<-p.release
	return nil
}
func TestNativeInputCallbackEndRunsAfterProxyCleanup(t *testing.T) {
	base := &pureNativeCallbackProxy{make(chan struct{}), make(chan struct{})}
	factory := &pureNativeCallbackFactory{make(chan struct{})}
	proxy := &nativeInputProxy{base: base, factory: factory}
	finished := make(chan struct{})
	go func() { defer close(finished); _ = proxy.Process(context.Background(), net.Network_TCP, nil, nil) }()
	select {
	case <-base.entered:
	case <-time.After(time.Second):
		t.Fatal("controlled proxy did not enter")
	}
	select {
	case <-factory.ended:
		t.Fatal("native callback ended before underlying SOCKS cleanup")
	default:
	}
	close(base.release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("controlled callback did not finish")
	}
	select {
	case <-factory.ended:
	default:
		t.Fatal("native callback completion missing")
	}
}
