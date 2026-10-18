package core

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// Value-only partial Instance and fake features; never Core.New/Start or sockets.
type nativePartialFeature struct{ closes int }

func (*nativePartialFeature) Type() any            { return (*nativePartialFeature)(nil) }
func (*nativePartialFeature) Start() error         { return nil }
func (feature *nativePartialFeature) Close() error { feature.closes++; return nil }

type nativeEssentialDelegate struct {
	instance *Instance
	t        *testing.T
	calls    int
}

func (delegate *nativeEssentialDelegate) LookupIPContext(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
	delegate.calls++
	if FromContext(ctx) != delegate.instance {
		delegate.t.Fatal("Essential DNS lost its exact constructing Core")
	}
	return []net.IP{{192, 0, 2, 19}}, 27, nil
}

func TestNativeLocalEssentialDefaultCapturesCoreWithoutFactoryOrExtraScope(t *testing.T) {
	delegate := &nativeEssentialDelegate{t: t}
	instance := &Instance{ctx: dns.ContextWithNativeLocalResolver(context.Background(), delegate)}
	delegate.instance = instance
	client := nativeLocalEssentialClient(instance).(*localdns.Client)
	defer client.Close()
	if delegate.calls != 0 {
		t.Fatal("Essential constructor queried before readiness")
	}
	ips, ttl, err := client.LookupIP("caller.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ttl != 27 || delegate.calls != 1 {
		t.Fatal("Essential default failed to use captured native delegate")
	}
	instance.features = []features.Feature{client}
	if nativeLocalEssentialClient(instance) != nil {
		t.Fatal("Existing scoped DNS caused an unused extra client lifetime")
	}
	instance.ctx = context.Background()
	legacy := nativeLocalEssentialClient(instance)
	if legacy == nil {
		t.Fatal("Unscoped essential construction changed")
	}
	_ = legacy.Close()
}

func TestNativeLocalPartialCoreCleanupIsOptInAndClosesUnaddedHandlers(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		ctx := context.Background()
		if scoped {
			ctx = dns.ContextWithNativeLocalResolver(ctx, nil)
		}
		feature, unadded := &nativePartialFeature{}, &nativePartialFeature{}
		partial := &Instance{ctx: ctx, features: []features.Feature{feature}}
		closeNativeDNSUnaddedHandler(ctx, unadded)
		closeNativeDNSPartialInstance(partial)
		want := 0
		if scoped {
			want = 1
		}
		if feature.closes != want || unadded.closes != want {
			t.Fatal("Scoped resource leaked or legacy behavior changed")
		}
	}
}
