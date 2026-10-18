package routing

import (
	"context"
	"net"
	"testing"
)

type testNativeInputFactory struct{}

func (*testNativeInputFactory) BindInput(context.Context, any, any, any, Dispatcher) (Dispatcher, error) {
	return nil, ErrNativeInput
}
func (*testNativeInputFactory) BeginInput(context.Context, any, any, any, net.Conn) (context.Context, func(), error) {
	return nil, nil, ErrNativeInput
}
func TestNativeInputFactoryPresenceIsStrict(t *testing.T) {
	if factory, present := NativeInputFactoryFromContext(context.Background()); factory != nil || present {
		t.Fatal("legacy context gained native authority")
	}
	for _, factory := range []NativeInputFactory{nil, (*testNativeInputFactory)(nil)} {
		if value, present := NativeInputFactoryFromContext(ContextWithNativeInputFactory(context.Background(), factory)); value != nil || !present {
			t.Fatal("unusable strict scope lost presence")
		}
	}
	factory := &testNativeInputFactory{}
	if value, present := NativeInputFactoryFromContext(ContextWithNativeInputFactory(context.Background(), factory)); value != factory || !present {
		t.Fatal("factory identity changed")
	}
}
