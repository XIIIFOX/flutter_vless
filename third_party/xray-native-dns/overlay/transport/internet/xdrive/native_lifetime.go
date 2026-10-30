package xdrive

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// NativeLifetime is owned by one Core instance, not by a process or a request.
// Storage identity additionally includes the actual compiled stream pointer:
// identical cloud credentials must not reuse another handler's socket policy.
type NativeLifetime struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
	storage map[nativeStorageKey]Storage
}

type nativeLifetimeKey struct{}
type nativeStorageKey struct {
	stream   *internet.MemoryStreamConfig
	identity string
}

func (n *NativeLifetime) Done() <-chan struct{} { return n.ctx.Done() }

func ContextWithNativeLifetime(parent context.Context) (context.Context, *NativeLifetime) {
	ctx, cancel := context.WithCancel(parent)
	owner := &NativeLifetime{cancel: cancel, storage: make(map[nativeStorageKey]Storage)}
	owner.ctx = context.WithValue(ctx, nativeLifetimeKey{}, owner)
	return owner.ctx, owner
}

// Close cancels requests and every TCP/QUIC pool before dropping cloud caches.
// It is safe on partial construction and repeated Core.Close calls.
func (n *NativeLifetime) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	retained := n.storage
	n.storage = nil
	n.mu.Unlock()
	n.cancel()
	for _, storage := range retained {
		_ = storage.Close()
	}
}

func nativeLifetimeContext(contexts []context.Context) context.Context {
	if len(contexts) != 0 && contexts[0] != nil {
		return contexts[0]
	}
	return context.Background()
}

// Keep the request's Core/handler values, while cancellation is also owned by
// its Core. This closes retry/backoff loops, not only an individual HTTP dial.
func nativeOperationContext(ctx, owner context.Context) (context.Context, func()) {
	if owner == nil {
		return ctx, func() {}
	}
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(owner, cancel)
	if owner.Err() != nil {
		cancel()
	}
	return operation, func() { stop(); cancel() }
}

// Direct upstream transport tests retain their original standalone constructor.
// Every real Core.New/NewWithContext installs an owner before constructing apps.
func newNativeStorage(ctx context.Context, stream *internet.MemoryStreamConfig) (Storage, error) {
	if stream == nil {
		return nil, errors.New("Invalid XDRIVE stream")
	}
	owner, owned := ctx.Value(nativeLifetimeKey{}).(*NativeLifetime)
	if !owned {
		return newStorage(stream)
	}
	config, err := streamConfig(stream)
	if err != nil {
		return nil, err
	}
	if config.Service != "s3" && config.Service != "google-drive" && config.Service != "Google Drive" {
		return newStorage(stream)
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.ctx.Err() != nil {
		return nil, errors.New("XDRIVE Core lifetime is closed")
	}
	key := nativeStorageKey{stream: stream, identity: shareKey(stream, config)}
	if storage := owner.storage[key]; storage != nil {
		return storage, nil
	}
	var storage Storage
	if config.Service == "s3" {
		storage, err = newS3Storage(stream, config, owner.ctx)
	} else {
		storage, err = newDriveStorage(stream, config, owner.ctx)
	}
	if err != nil {
		return nil, err
	}
	owner.storage[key] = storage
	return storage, nil
}
