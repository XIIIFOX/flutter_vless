package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
)

type balancerObserverKey struct{}

type balancerObserver struct {
	inboundTag string
	observe    func(group, node string)
}

// ContextWithBalancerObserver installs a construction-time, in-process sink.
// The dispatcher borrows routing tags only. It never passes the route or session
// object, which may contain traffic metadata, to the sink.
func ContextWithBalancerObserver(ctx context.Context, managedInbound string, observe func(group, node string)) context.Context {
	return context.WithValue(ctx, balancerObserverKey{}, &balancerObserver{managedInbound, observe})
}

func balancerObserverFromContext(ctx context.Context) *balancerObserver {
	observer, _ := ctx.Value(balancerObserverKey{}).(*balancerObserver)
	return observer
}

func (o *balancerObserver) record(ctx context.Context, route routing.Route, outboundTag string) {
	if o == nil || route == nil || outboundTag == "" || ctx.Err() != nil {
		return
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "socks" || inbound.Tag != o.inboundTag {
		return
	}
	for _, group := range route.GetOutboundGroupTags() {
		o.observe(group, outboundTag)
	}
}
