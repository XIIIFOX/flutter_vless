package nativeinstance

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

func TestNativeManagedUDPGrantRetainedUntilWholeCallbackFinalizer(t *testing.T) {
	r, dispatcher, _, parent := managedRuntime(t, &fakeCore{})
	admit := func() (context.Context, context.CancelFunc, func()) {
		caller, cancel := context.WithCancel(parent)
		conn := newFakeManagedConn()
		ctx := session.ContextWithInbound(caller, &session.Inbound{Conn: conn})
		operation, end, err := r.input.BeginInput(ctx, r.input.instance, r.input.selected, r.input.handlers[r.input.selected], conn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(end)
		t.Cleanup(cancel)
		return operation, cancel, end
	}
	a, cancelA, endA := admit()
	b, _, _ := admit()
	peer := netip.MustParseAddrPort("127.0.0.1:34567")
	other := netip.MustParseAddrPort("127.0.0.1:34568")
	if _, err := dispatcher.Dispatch(a, xnet.UDPDestination(xnet.LocalHostIP, 53)); !errors.Is(err, routing.ErrNativeInput) {
		t.Fatal("UDP flow admitted without a post-auth association grant")
	}
	for _, bad := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("127.0.0.2:34567"), netip.MustParseAddrPort("[::1]:34567")} {
		if r.input.AuthorizeUDPAssociation(a, bad) == nil {
			t.Fatal("non-concrete loopback peer admitted")
		}
	}
	for _, bad := range []context.Context{parent, context.Background(), context.WithValue(a, core.XrayKey(1), &core.Instance{}), session.ContextWithInbound(a, &session.Inbound{Conn: newFakeManagedConn()})} {
		if r.input.AuthorizeUDPAssociation(bad, peer) == nil {
			t.Fatal("detached/substituted association admitted")
		}
	}
	if err := r.input.AuthorizeUDPAssociation(a, peer); err != nil {
		t.Fatal("concrete peer refused", err)
	}
	if r.input.AuthorizeUDPAssociation(a, other) == nil {
		t.Fatal("one control acquired two grants")
	}
	if r.input.AuthorizeUDPAssociation(b, peer) == nil {
		t.Fatal("second control stole active tuple")
	}
	cancelA()
	<-a.Done()
	if r.input.AuthorizeUDPAssociation(b, peer) == nil {
		t.Fatal("cancel released tuple before SOCKS finalizer")
	}
	endA()
	if err := r.input.AuthorizeUDPAssociation(b, peer); err != nil {
		t.Fatal("completed callback retained tuple", err)
	}
	if r.input.AuthorizeUDPAssociation(a, other) == nil {
		t.Fatal("closed callback replay acquired grant")
	}
}

func TestNativeManagedUDPImportedCallbackKeepsLegacyWithoutPrivateAuthority(t *testing.T) {
	r, dispatcher, _, parent := managedRuntime(t, &fakeCore{})
	var source *core.InboundHandlerConfig
	for key := range r.input.known {
		if key != r.input.selected {
			source = key
			break
		}
	}
	if source == nil {
		t.Fatal("source input missing")
	}
	conn := newFakeManagedConn()
	ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: conn})
	op, end, err := r.input.BeginInput(ctx, r.input.instance, source, r.input.handlers[source], conn)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	if err := r.input.AuthorizeUDPAssociation(op, netip.AddrPort{}); err != nil {
		t.Fatal("imported legacy UDP semantics changed")
	}
	// Even an internal copy of the generic capsule into the private context key
	// cannot turn an imported source callback into selected-input authority.
	forged := context.WithValue(op, managedConnectionKey{}, op.Value(ownedInputConnectionKey{}))
	if _, err := dispatcher.Dispatch(forged, xnet.UDPDestination(xnet.LocalHostIP, 53)); err == nil {
		t.Fatal("imported capsule reached private dispatcher")
	}
}
