package internet

import (
	"context"
	"errors"
	"io"
	"sync"
)

// NativeServiceLifetime is a low-level Core-owned cancellation/resource registry.
// It must not import transport implementations, which can depend on Core.
type NativeServiceLifetime struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	closed    bool
	resources map[any]io.Closer
}

type nativeServiceLifetimeKey struct{}

func ContextWithNativeServiceLifetime(parent context.Context) (context.Context, *NativeServiceLifetime) {
	ctx, cancel := context.WithCancel(parent)
	owner := &NativeServiceLifetime{cancel: cancel, resources: make(map[any]io.Closer)}
	owner.ctx = context.WithValue(ctx, nativeServiceLifetimeKey{}, owner)
	return owner.ctx, owner
}

func NativeServiceLifetimeFromContext(ctx context.Context) (*NativeServiceLifetime, bool) {
	if ctx == nil {
		return nil, false
	}
	owner, ok := ctx.Value(nativeServiceLifetimeKey{}).(*NativeServiceLifetime)
	return owner, ok && owner != nil
}

func (n *NativeServiceLifetime) Done() <-chan struct{} { return n.ctx.Done() }
func (n *NativeServiceLifetime) ResourceCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.resources)
}

// Keys are private, comparable identities supplied by a transport, never JSON.
// Construction is lazy and performs no network operation under this mutex.
func (n *NativeServiceLifetime) Resource(key any, build func(context.Context) (io.Closer, error)) (io.Closer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.ctx.Err() != nil {
		return nil, errors.New("Core service lifetime is closed")
	}
	if value := n.resources[key]; value != nil {
		return value, nil
	}
	value, err := build(n.ctx)
	if err != nil {
		return nil, err
	}
	n.resources[key] = value
	return value, nil
}

func (n *NativeServiceLifetime) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	retained := n.resources
	n.resources = nil
	n.mu.Unlock()
	n.cancel()
	for _, value := range retained {
		_ = value.Close()
	}
}
