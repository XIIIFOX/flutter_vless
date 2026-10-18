package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

type nativeLocalNilResolver struct{}

func (*nativeLocalNilResolver) LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error) {
	panic("A nil native delegate must not be called")
}

func TestNativeLocalResolverPresenceCannotBecomeLegacyFallback(t *testing.T) {
	if resolver, present := NativeLocalResolverFromContext(context.Background()); resolver != nil || present {
		t.Fatal("Unscoped context gained a native delegate")
	}
	for _, resolver := range []NativeLocalResolver{nil, (*nativeLocalNilResolver)(nil)} {
		ctx := ContextWithNativeLocalResolver(context.Background(), resolver)
		if value, present := NativeLocalResolverFromContext(ctx); !present || value != nil {
			t.Fatal("Unusable strict scope was confused with absence")
		}
	}
	resolver := &nativeLocalNilResolver{}
	ctx := ContextWithNativeLocalResolver(context.Background(), resolver)
	if value, present := NativeLocalResolverFromContext(ctx); !present || value != resolver {
		t.Fatal("Native delegate identity was not retained")
	}
}
