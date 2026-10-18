package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

// Memory delegates only: no Core factory, real resolver, dispatcher or socket.
type nativeAppLocalDelegate struct {
	calls atomic.Int64
	query func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error)
}

func (delegate *nativeAppLocalDelegate) LookupIPContext(ctx context.Context, name string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	delegate.calls.Add(1)
	return delegate.query(ctx, name, option)
}

func TestNativeLocalAppImplicitBoundStrategyAndClose(t *testing.T) {
	delegate := &nativeAppLocalDelegate{query: func(ctx context.Context, name string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
		if name != "caller.invalid" || !option.IPv4Enable || option.IPv6Enable {
			t.Fatal("Root query strategy/name changed")
		}
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || time.Until(deadline) < 3*time.Second || time.Until(deadline) > featureDNS.NativeLocalResolverTimeout {
			t.Fatal("Implicit timeout zero or unbounded")
		}
		return []net.IP{{192, 0, 2, 18}}, 91, nil
	}}
	ctx := featureDNS.ContextWithNativeLocalResolver(context.Background(), delegate)
	server, err := New(ctx, &Config{QueryStrategy: QueryStrategy_USE_IP4})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if delegate.calls.Load() != 0 || len(server.clients) != 1 {
		t.Fatal("Construction queried or changed implicit client count")
	}
	if _, ok := server.clients[0].server.(*LocalNameServer); !ok || server.clients[0].Name() != "localhost" {
		t.Fatal("Local matcher identity changed")
	}
	ips, ttl, err := server.LookupIP("caller.invalid", featureDNS.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil || ttl != 91 || len(ips) != 1 || ips[0].String() != "192.0.2.18" || delegate.calls.Load() != 1 {
		t.Fatal("Root DNS did not return delegate answer")
	}
	_ = server.Close()
	if _, _, err := server.LookupIP("caller.invalid", featureDNS.IPOption{IPv4Enable: true}); !errors.Is(err, featureDNS.ErrNativeLocalResolverClosed) {
		t.Fatal("Root Close left local client usable")
	}
}

func TestNativeLocalAppExplicitLocalhostHonorsRequestCancellation(t *testing.T) {
	request, cancel := context.WithCancel(context.Background())
	delegate := &nativeAppLocalDelegate{query: func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error) {
		cancel()
		return []net.IP{{192, 0, 2, 18}}, 91, nil
	}}
	creation := featureDNS.ContextWithNativeLocalResolver(context.Background(), delegate)
	server, err := NewServer(creation, net.UDPDestination(net.DomainAddress("localhost"), 53), nil, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, ok := server.(*LocalNameServer)
	if !ok || local.Name() != "localhost" {
		t.Fatal("Explicit localhost type changed")
	}
	defer local.closeNativeLocal()
	if _, _, err := local.QueryIP(request, "caller.invalid", featureDNS.IPOption{IPv4Enable: true}); !errors.Is(err, context.Canceled) {
		t.Fatal("LocalNameServer ignored query cancellation")
	}
}

func TestNativeLocalAppLegacyImplicitConstructorUnchanged(t *testing.T) {
	legacy := NewLocalDNSClientWithContext(context.Background(), featureDNS.IPOption{IPv4Enable: true})
	if legacy.timeoutMs != 0 || legacy.Name() != "localhost" {
		t.Fatal("Legacy implicit client behavior changed")
	}
	if err := legacy.server.(*LocalNameServer).closeNativeLocal(); err != nil {
		t.Fatal(err)
	}
}
