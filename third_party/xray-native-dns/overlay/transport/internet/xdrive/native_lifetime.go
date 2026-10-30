package xdrive

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// NativeLifetime is owned by one Core instance, not by a process or a request.
// Storage identity additionally includes the actual compiled stream pointer:
// identical cloud credentials must not reuse another handler's socket policy.
type NativeLifetime = internet.NativeServiceLifetime
type nativeStorageKey struct {
	stream   *internet.MemoryStreamConfig
	identity string
}

func ContextWithNativeLifetime(parent context.Context) (context.Context, *NativeLifetime) {
	_, owner := internet.ContextWithNativeServiceLifetime(parent)
	return owner.ServiceContext(), owner
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
	owner, owned := internet.NativeServiceLifetimeFromContext(ctx)
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
	key := nativeStorageKey{stream: stream, identity: shareKey(stream, config)}
	resource, err := owner.Resource(key, func(ownerContext context.Context) (io.Closer, error) {
		if config.Service == "s3" {
			return newS3Storage(stream, config, ownerContext)
		}
		return newDriveStorage(stream, config, ownerContext)
	})
	if err != nil {
		return nil, err
	}
	storage, ok := resource.(Storage)
	if !ok {
		return nil, errors.New("Invalid XDRIVE owned resource")
	}
	return storage, nil
}
