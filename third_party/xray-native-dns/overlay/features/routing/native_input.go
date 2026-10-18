package routing

import (
	"context"
	"errors"
	"net"
	"reflect"
)

// Unpublished construction-only seam. No Core/app/nativeinstance import: the
// trusted host binds exact compiled keys before construction, then seals them.
// A request's tag/session metadata is never a grant of native input authority.
type NativeInputFactory interface {
	BindInput(context.Context, any, any, any, Dispatcher) (Dispatcher, error)
	BeginInput(context.Context, any, any, any, net.Conn) (context.Context, func(), error)
}

type nativeInputFactoryKey struct{}

var ErrNativeInput = errors.New("native managed input unavailable")

func ContextWithNativeInputFactory(ctx context.Context, factory NativeInputFactory) context.Context {
	return context.WithValue(ctx, nativeInputFactoryKey{}, struct{ Factory NativeInputFactory }{factory})
}
func NativeInputFactoryFromContext(ctx context.Context) (NativeInputFactory, bool) {
	if ctx == nil {
		return nil, false
	}
	value, present := ctx.Value(nativeInputFactoryKey{}).(struct{ Factory NativeInputFactory })
	if !present || value.Factory == nil {
		return nil, present
	}
	reflected := reflect.ValueOf(value.Factory)
	if reflected.Kind() == reflect.Pointer && reflected.IsNil() {
		return nil, true
	}
	return value.Factory, true
}
