package dns

// Internal, unpublished opt-in seam. It deliberately imports no Core, app/dns,
// transport, or native host package: those layers can implement the delegate.
import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// NativeLocalResolver must be closed-to-query until its owning Core has finished
// construction and its independent native DNS transport is ready. Implementations
// own readiness, lifetime, cancellation of active exchanges, and late results.
// They must never resolve through the root DNS feature they are serving.
type NativeLocalResolver interface {
	LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error)
}

// A strict native local lookup is bounded even when called through dns.Client's
// context-free compatibility method or the implicit localhost client.
const NativeLocalResolverTimeout = 4 * time.Second

var (
	ErrNativeLocalResolverUnavailable = errors.New("native local DNS unavailable")
	ErrNativeLocalResolverClosed      = errors.New("native local DNS client closed")
)

type nativeLocalResolverKey struct{}
type nativeLocalResolverBinding struct{ resolver NativeLocalResolver }

func ContextWithNativeLocalResolver(ctx context.Context, resolver NativeLocalResolver) context.Context {
	// A wrapper preserves presence even for a nil/typed-nil delegate. A broken
	// strict scope must never be mistaken for permission to use legacy OS DNS.
	return context.WithValue(ctx, nativeLocalResolverKey{}, nativeLocalResolverBinding{resolver})
}

func NativeLocalResolverFromContext(ctx context.Context) (NativeLocalResolver, bool) {
	if ctx == nil {
		return nil, false
	}
	binding, present := ctx.Value(nativeLocalResolverKey{}).(nativeLocalResolverBinding)
	if !present || binding.resolver == nil {
		return nil, present
	}
	value := reflect.ValueOf(binding.resolver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, true
		}
	}
	return binding.resolver, true
}
