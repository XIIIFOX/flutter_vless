package socks

import (
	"context"
	"net/netip"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// Legacy Core has no construction factory. A present but unusable factory must
// never silently acquire legacy first-datagram association semantics.
func authorizeNativeUDP(ctx context.Context, address net.Address, port net.Port) error {
	factory, present := routing.NativeInputFactoryFromContext(ctx)
	if !present {
		return nil
	}
	authorizer, ok := factory.(routing.NativeUDPAssociationAuthorizer)
	if !ok || authorizer == nil || ctx == nil || ctx.Err() != nil {
		return routing.ErrNativeInput
	}
	var peer netip.AddrPort
	if address != nil && address.Family().IsIP() {
		if ip, ok := netip.AddrFromSlice(address.IP()); ok {
			peer = netip.AddrPortFrom(ip.Unmap(), uint16(port))
		}
	}
	if authorizer.AuthorizeUDPAssociation(ctx, peer) != nil {
		return routing.ErrNativeInput
	}
	return nil
}
