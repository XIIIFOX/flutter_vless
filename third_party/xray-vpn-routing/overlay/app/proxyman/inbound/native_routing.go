package inbound

import (
	"context"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Called after the real AlwaysOn constructor and before handler publication.
// Only the exact compiled private key is selected; caller/API handlers retain
// their original proxy, workers, interfaces, routing and lifetime behavior.
func bindNativeRoutingInput(ctx context.Context, config *core.InboundHandlerConfig, h *AlwaysOnInboundHandler) error {
	owner, present := routing.NativeRoutingOwnerFromContext(ctx)
	if !present {
		return nil
	}
	if owner == nil || h == nil {
		return routing.ErrNativeRoutingScope
	}
	instance := core.FromContext(ctx)
	input, err := owner.BindInput(ctx, instance, config, h)
	if err != nil || input == nil {
		return err
	}
	tcp, ok := nativeRoutingTCPControl(h, instance)
	if !ok {
		_ = input.Close()
		return routing.ErrNativeRoutingPolicy
	}
	for user := range h.proxyConfig.(*socks.ServerConfig).Accounts {
		if err := input.ValidateAuthUser(user); err != nil {
			_ = input.Close()
			return err
		}
	}
	p := &nativeRoutingInboundProxy{Inbound: h.proxy, input: input, handler: h}
	h.proxy = p
	tcp.proxy = p
	// AlwaysOn.Close visits workers before h.proxy. Revoke before the worker
	// closes its listener, rather than waiting for the final proxy Close call.
	h.workers[0] = &nativeRoutingInboundWorker{worker: tcp, proxy: p}
	return nil
}

func nativeRoutingTCPControl(h *AlwaysOnInboundHandler, instance *core.Instance) (*tcpWorker, bool) {
	s, ok := h.proxyConfig.(*socks.ServerConfig)
	if !ok || s == nil || s.AuthType != socks.AuthType_PASSWORD || len(s.Accounts) != 1 || h.proxy == nil {
		return nil, false
	}
	for user, password := range s.Accounts {
		if user == "" || password == "" {
			return nil, false
		}
	}
	r := h.receiverConfig
	if r == nil || r.Listen == nil || r.PortList == nil || len(r.PortList.Range) != 1 || r.ReceiveOriginalDestination || len(h.workers) != 1 {
		return nil, false
	}
	address := r.Listen.AsAddress()
	if address == nil || !address.Family().IsIP() || !address.IP().IsLoopback() {
		return nil, false
	}
	port := r.PortList.Range[0]
	if port == nil || port.From == 0 || port.From > 65535 || port.From != port.To {
		return nil, false
	}
	if stream := r.StreamSettings; stream != nil && (stream.SecurityType != "" || len(stream.SecuritySettings) != 0 ||
		(stream.ProtocolName != "" && stream.ProtocolName != "tcp")) {
		return nil, false
	}
	networks := h.proxy.Network()
	if len(networks) != 1 || networks[0] != net.Network_TCP {
		return nil, false
	}
	w, ok := h.workers[0].(*tcpWorker)
	if !ok || w.ctx == nil || core.FromContext(w.ctx) != instance || w.proxy != h.proxy || w.tag != h.tag ||
		w.address == nil || !w.address.Family().IsIP() || !w.address.IP().Equal(address.IP()) || w.port.Value() != uint16(port.From) {
		return nil, false
	}
	return w, true
}

type nativeRoutingInboundProxy struct {
	proxy.Inbound
	input   *routing.NativeRoutingInput
	handler *AlwaysOnInboundHandler
	once    sync.Once
	err     error
}

func (p *nativeRoutingInboundProxy) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	// Never replace the connection or lend a capsule to borrowed metadata.
	// tcpWorker's stats wrapper is already installed in both positions here.
	if inbound == nil || network != net.Network_TCP || conn == nil || reflect.ValueOf(conn).Kind() != reflect.Pointer ||
		reflect.ValueOf(conn).IsNil() || inbound.Conn != conn {
		return routing.ErrNativeRoutingScope
	}
	bound, release, err := p.input.Begin(ctx, core.FromContext(ctx), p.handler, routing.NativeRoutingMetadata{Conn: conn, Tag: inbound.Tag})
	if err != nil {
		return err
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(bound, func() { defer close(closed); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
		release()
	}()
	if err := bound.Err(); err != nil {
		return err
	}
	// Authentication and Name/User population remain the real SOCKS server's
	// work. The policy grants nothing until the later routedDispatch hook.
	return p.Inbound.Process(bound, network, conn, dispatcher)
}

func (p *nativeRoutingInboundProxy) Close() error {
	p.once.Do(func() {
		_ = p.input.Close()
		p.err = common.Close(p.Inbound)
	})
	return p.err
}

type nativeRoutingInboundWorker struct {
	worker
	proxy *nativeRoutingInboundProxy
}

func (w *nativeRoutingInboundWorker) Close() error {
	return errors.Combine(w.proxy.Close(), w.worker.Close())
}
