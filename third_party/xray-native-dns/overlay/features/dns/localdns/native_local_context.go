package localdns

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type nativeLocalState struct {
	resolver dns.NativeLocalResolver
	creation context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
}

// NewWithContext captures construction scope without querying, waiting for
// readiness, or allocating an OS dialer in strict mode. New() remains legacy.
func NewWithContext(ctx context.Context) *Client {
	resolver, scoped := dns.NativeLocalResolverFromContext(ctx)
	if !scoped {
		return New()
	}
	creation, cancel := context.WithCancel(ctx)
	return &Client{native: &nativeLocalState{resolver: resolver, creation: creation, cancel: cancel}}
}

// Current request values take precedence, so a foreign owner's context can still
// be rejected by the native delegate. Detached requests recover missing Core /
// owner values from construction. No request context is stored in the client.
type nativeLocalQueryContext struct {
	context.Context
	creation context.Context
}

func (ctx nativeLocalQueryContext) Value(key any) any {
	if value := ctx.Context.Value(key); value != nil {
		return value
	}
	return ctx.creation.Value(key)
}

func (c *Client) closeNativeLocal() error {
	if c.native != nil {
		c.native.closed.Store(true)
		c.native.cancel()
	}
	return nil
}

// LookupIPContext is additive: unscoped clients retain their original resolver
// behavior, including the legacy context-free path. Strict delegates never enter
// that branch, even if missing, not-ready, failed, cancelled or already closed.
func (c *Client) LookupIPContext(ctx context.Context, host string, option dns.IPOption) ([]net.IP, uint32, error) {
	state := c.native
	if state == nil {
		return c.LookupIP(host, option)
	}
	if state.closed.Load() {
		return nil, 0, dns.ErrNativeLocalResolverClosed
	}
	if ctx == nil || state.resolver == nil {
		return nil, 0, dns.ErrNativeLocalResolverUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if err := state.creation.Err(); err != nil {
		return nil, 0, err
	}
	deadline := time.Now().Add(dns.NativeLocalResolverTimeout)
	if creationDeadline, ok := state.creation.Deadline(); ok && creationDeadline.Before(deadline) {
		deadline = creationDeadline
	}
	operation, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(state.creation, cancel)
	defer func() { stop(); cancel() }()
	owned := nativeLocalQueryContext{Context: operation, creation: state.creation}
	ips, ttl, err := state.resolver.LookupIPContext(owned, host, option)
	if state.closed.Load() {
		return nil, 0, dns.ErrNativeLocalResolverClosed
	}
	if cancellation := state.creation.Err(); cancellation != nil {
		return nil, 0, cancellation
	}
	if cancellation := operation.Err(); cancellation != nil {
		return nil, 0, cancellation
	}
	if err != nil {
		return nil, 0, err
	}
	if len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}
	// The delegate may cache its answers; do not hand its mutable slices to a
	// caller, or retain any mutable data from this request in the client.
	answer := make([]net.IP, len(ips))
	for index, ip := range ips {
		answer[index] = append(net.IP(nil), ip...)
	}
	return answer, ttl, nil
}
