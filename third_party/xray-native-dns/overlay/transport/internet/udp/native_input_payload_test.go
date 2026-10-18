package udp

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type refusedNativeDispatcher struct{ calls int }

func (*refusedNativeDispatcher) Type() any    { return routing.DispatcherType() }
func (*refusedNativeDispatcher) Start() error { return nil }
func (*refusedNativeDispatcher) Close() error { return nil }
func (d *refusedNativeDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	d.calls++
	return nil, errors.New("fixed admission refused")
}
func (*refusedNativeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return errors.New("unused")
}
func TestNativeInputAdmissionErrorReleasesOwnedPayload(t *testing.T) {
	base := &refusedNativeDispatcher{}
	dispatcher := NewDispatcher(base, func(context.Context, *protocoludp.Packet) {})
	target := net.UDPDestination(net.LocalHostIP, 53)
	for i := 0; i < 32; i++ {
		payload := buf.New()
		_, _ = payload.Write([]byte{1, 2, 3})
		payload.UDP = &target
		dispatcher.Dispatch(context.Background(), target, payload)
		if payload.Len() != 0 || payload.UDP != nil {
			t.Fatal("refused dispatch leaked its owned payload")
		}
	}
	if base.calls != 32 {
		t.Fatal("control did not exercise every admission refusal")
	}
	dispatcher.RemoveRay()
}
