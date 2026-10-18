package core

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// The scoped default must capture the exact constructing Core, including when
// no app/dns feature exists. Avoid a second unused scope when it already does.
// Unscoped construction retains the upstream eager legacy client behavior.
func nativeLocalEssentialClient(server *Instance) features.Feature {
	if _, scoped := dns.NativeLocalResolverFromContext(server.ctx); scoped && server.GetFeature(dns.ClientType()) != nil {
		return nil
	}
	return localdns.NewWithContext(toContext(server.ctx, server))
}

// Only opt-in construction owns these new cleanup semantics. The delegate / its
// native adapter is separately owned by the native caller, not closed here.
func closeNativeDNSPartialInstance(server *Instance) {
	if _, scoped := dns.NativeLocalResolverFromContext(server.ctx); scoped {
		_ = server.Close()
	}
}

func closeNativeDNSUnaddedHandler(ctx context.Context, handler common.Closable) {
	if _, scoped := dns.NativeLocalResolverFromContext(ctx); scoped {
		_ = handler.Close()
	}
}
