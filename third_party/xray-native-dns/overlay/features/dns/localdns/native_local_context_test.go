package localdns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// All delegates are memory-only. No Core, real resolver or socket is started.
type nativeLocalDelegate struct {
	calls atomic.Int64
	query func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error)
}

func (delegate *nativeLocalDelegate) LookupIPContext(ctx context.Context, host string, option dns.IPOption) ([]net.IP, uint32, error) {
	delegate.calls.Add(1)
	return delegate.query(ctx, host, option)
}

func nativeLocalAnswer() ([]net.IP, uint32, error) { return []net.IP{{192, 0, 2, 17}}, 37, nil }
func nativeLocalClient(delegate dns.NativeLocalResolver) *Client {
	return NewWithContext(dns.ContextWithNativeLocalResolver(context.Background(), delegate))
}

func TestNativeLocalClientBeforeReadyAndUnusableScope(t *testing.T) {
	ready := false
	delegate := &nativeLocalDelegate{query: func(ctx context.Context, host string, option dns.IPOption) ([]net.IP, uint32, error) {
		if !ready {
			return nil, 0, dns.ErrNativeLocalResolverUnavailable
		}
		if host != "caller.invalid" || !option.IPv4Enable || option.IPv6Enable {
			t.Fatal("Query was changed")
		}
		deadline, exists := ctx.Deadline()
		if !exists || time.Until(deadline) < 3*time.Second || time.Until(deadline) > dns.NativeLocalResolverTimeout {
			t.Fatal("Context-free native lookup lacks its nonzero hard bound")
		}
		return nativeLocalAnswer()
	}}
	client := nativeLocalClient(delegate)
	defer client.Close()
	if delegate.calls.Load() != 0 || client.d != nil || client.r != nil {
		t.Fatal("Strict construction queried or allocated legacy OS DNS")
	}
	option := dns.IPOption{IPv4Enable: true}
	if _, _, err := client.LookupIP("caller.invalid", option); !errors.Is(err, dns.ErrNativeLocalResolverUnavailable) {
		t.Fatal("Before-ready query did not fail closed")
	}
	ready = true
	ips, ttl, err := client.LookupIP("caller.invalid", option)
	if err != nil || ttl != 37 || len(ips) != 1 || ips[0].String() != "192.0.2.17" || delegate.calls.Load() != 2 {
		t.Fatal("Actual delegate answer was lost")
	}
	for _, bad := range []dns.NativeLocalResolver{nil, (*nativeLocalDelegate)(nil)} {
		broken := nativeLocalClient(bad)
		if _, _, err := broken.LookupIP("must-not-resolve.invalid", option); !errors.Is(err, dns.ErrNativeLocalResolverUnavailable) {
			t.Fatal("Unusable strict scope reached legacy DNS")
		}
		_ = broken.Close()
	}
}

func TestNativeLocalClientCloseRejectsEarlyAndDiscardsLateSuccess(t *testing.T) {
	var client *Client
	delegate := &nativeLocalDelegate{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) {
		_ = client.Close()
		return nativeLocalAnswer()
	}}
	client = nativeLocalClient(delegate)
	if _, _, err := client.LookupIP("caller.invalid", dns.IPOption{}); !errors.Is(err, dns.ErrNativeLocalResolverClosed) {
		t.Fatal("Late result escaped closed client")
	}
	if _, _, err := client.LookupIPContext(context.Background(), "caller.invalid", dns.IPOption{}); !errors.Is(err, dns.ErrNativeLocalResolverClosed) || delegate.calls.Load() != 1 {
		t.Fatal("Closed client called delegate")
	}
}

func TestNativeLocalClientCloseCancelsInFlightLookup(t *testing.T) {
	entered := make(chan struct{})
	delegate := &nativeLocalDelegate{query: func(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
		close(entered)
		<-ctx.Done()
		return nativeLocalAnswer()
	}}
	client := nativeLocalClient(delegate)
	finished := make(chan error, 1)
	go func() { _, _, err := client.LookupIP("caller.invalid", dns.IPOption{}); finished <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Memory delegate did not enter")
	}
	_ = client.Close()
	select {
	case err := <-finished:
		if !errors.Is(err, dns.ErrNativeLocalResolverClosed) {
			t.Fatal("Close returned late answer")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel pending lookup")
	}
}

func TestNativeLocalClientRequestAndCreationCancellationDiscardLateAnswers(t *testing.T) {
	for _, creation := range []bool{false, true} {
		parent, cancelParent := context.WithCancel(context.Background())
		request, cancelRequest := context.WithCancel(context.Background())
		delegate := &nativeLocalDelegate{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) {
			if creation {
				cancelParent()
			} else {
				cancelRequest()
			}
			return nativeLocalAnswer()
		}}
		client := NewWithContext(dns.ContextWithNativeLocalResolver(parent, delegate))
		if _, _, err := client.LookupIPContext(request, "caller.invalid", dns.IPOption{}); !errors.Is(err, context.Canceled) {
			t.Fatal("Cancelled operation returned late result")
		}
		_ = client.Close()
		cancelParent()
		cancelRequest()
	}
	request, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	delegate := &nativeLocalDelegate{query: func(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Millisecond {
			t.Fatal("Caller deadline extended")
		}
		<-ctx.Done()
		return nativeLocalAnswer()
	}}
	client := nativeLocalClient(delegate)
	defer client.Close()
	if _, _, err := client.LookupIPContext(request, "caller.invalid", dns.IPOption{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Expired deadline returned late result")
	}
}

func TestNativeLocalClientAlreadyCancelledDoesNotInvokeDelegate(t *testing.T) {
	for _, cancelledCreation := range []bool{false, true} {
		creation, cancelCreation := context.WithCancel(context.Background())
		request, cancelRequest := context.WithCancel(context.Background())
		delegate := &nativeLocalDelegate{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) {
			t.Fatal("Already cancelled strict lookup invoked resolver")
			return nativeLocalAnswer()
		}}
		client := NewWithContext(dns.ContextWithNativeLocalResolver(creation, delegate))
		if cancelledCreation {
			cancelCreation()
		} else {
			cancelRequest()
		}
		if _, _, err := client.LookupIPContext(request, "must-not-resolve.invalid", dns.IPOption{}); !errors.Is(err, context.Canceled) || delegate.calls.Load() != 0 {
			t.Fatal("Cancelled strict scope did not fail before resolution")
		}
		_ = client.Close()
		cancelRequest()
		cancelCreation()
	}
}

func TestNativeLocalClientKeepsCurrentAndCreationContextButCopiesAnswers(t *testing.T) {
	type key int
	const creationKey, requestKey key = 1, 2
	shared := net.IP{192, 0, 2, 17}
	seen := []string{}
	delegate := &nativeLocalDelegate{query: func(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
		if ctx.Value(creationKey) != "captured-core" {
			t.Fatal("Detached query lost creation context")
		}
		seen = append(seen, ctx.Value(requestKey).(string))
		return []net.IP{shared}, 37, nil
	}}
	creation := context.WithValue(context.Background(), creationKey, "captured-core")
	client := NewWithContext(dns.ContextWithNativeLocalResolver(creation, delegate))
	defer client.Close()
	for _, name := range []string{"first", "second"} {
		request, cancel := context.WithCancel(context.WithValue(context.Background(), requestKey, name))
		ips, _, err := client.LookupIPContext(request, "caller.invalid", dns.IPOption{})
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		ips[0][0] = 10
		if shared[0] != 192 {
			t.Fatal("Caller mutated cached delegate result")
		}
	}
	if len(seen) != 2 || seen[0] != "first" || seen[1] != "second" {
		t.Fatal("First request context retained")
	}
	// Preserve a foreign request identity rather than silently replacing it with
	// the captured owner. The adapter must see it and can reject that operation.
	foreign := context.WithValue(context.Background(), creationKey, "foreign-core")
	delegate.query = func(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
		if ctx.Value(creationKey) != "foreign-core" {
			t.Fatal("Captured context masked foreign request ownership")
		}
		return nil, 0, dns.ErrNativeLocalResolverUnavailable
	}
	if _, _, err := client.LookupIPContext(foreign, "caller.invalid", dns.IPOption{}); !errors.Is(err, dns.ErrNativeLocalResolverUnavailable) {
		t.Fatal("Foreign delegate rejection was hidden")
	}
}

func TestNativeLocalClientPreservesRCodeAndLegacyLiteralBehavior(t *testing.T) {
	refused := dns.RCodeError(5)
	delegate := &nativeLocalDelegate{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) { return nil, 0, refused }}
	client := nativeLocalClient(delegate)
	defer client.Close()
	if _, _, err := client.LookupIP("caller.invalid", dns.IPOption{}); !errors.Is(err, refused) {
		t.Fatal("DNS RCode rewritten")
	}
	legacy := NewWithContext(context.Background())
	if legacy.native != nil || legacy.d == nil || legacy.r == nil {
		t.Fatal("Legacy constructor changed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	// Numeric literal parsing requires no DNS or socket operation.
	ips, _, err := legacy.LookupIPContext(cancelled, "127.0.0.1", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatal("Legacy lookup behavior changed")
	}
	_ = legacy.Close()
}
