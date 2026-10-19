package core

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/routing"
)

// These are manually assembled, inert feature collections. No Core constructor,
// Start, listener, connection or application runtime is used by these tests.
type nativeConstructionFeature struct {
	close func() error
}

func (*nativeConstructionFeature) Type() interface{} { return (*nativeConstructionFeature)(nil) }
func (*nativeConstructionFeature) Start() error      { panic("inert feature must not start") }
func (f *nativeConstructionFeature) Close() error    { return f.close() }

type nativeConstructionHandler struct{}

func (*nativeConstructionHandler) Tag() string { return "managed" }

func nativeConstructionOwner(t *testing.T, server *Instance) (context.Context, *routing.NativeRoutingOwner, context.Context, routing.NativeRoutingMetadata) {
	t.Helper()
	key := &InboundHandlerConfig{Tag: "managed"}
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: key, ManagedTag: "managed", AuthUser: "private"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	ctx := routing.ContextWithNativeRoutingOwner(context.Background(), owner)
	handler := new(nativeConstructionHandler)
	input, err := owner.BindInput(ctx, server, key, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Seal(server); err != nil {
		t.Fatal(err)
	}
	meta := routing.NativeRoutingMetadata{Conn: new(struct{ n int }), Tag: "managed", User: "private"}
	control, end, err := input.Begin(ctx, server, handler, meta)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	route, release, err := owner.BeginRoute(control, server, meta)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return ctx, owner, route, meta
}

func TestNativeRoutingConstructionFailure(t *testing.T) {
	t.Run("legacy-not-closed", func(t *testing.T) {
		calls := 0
		server := &Instance{running: true, features: []features.Feature{&nativeConstructionFeature{close: func() error { calls++; return nil }}}}
		nativeRoutingConstructionFailed(context.Background(), server)
		if calls != 0 || !server.running {
			t.Fatal("ordinary NewWithContext failure cleanup behavior changed")
		}
	})
	t.Run("owner-revoked-before-feature-close", func(t *testing.T) {
		server := new(Instance)
		ctx, owner, route, meta := nativeConstructionOwner(t, server)
		calls := 0
		server.features = []features.Feature{&nativeConstructionFeature{close: func() error {
			calls++
			if route.Err() != context.Canceled {
				t.Error("feature close preceded owner context cancellation")
			}
			if _, selected, err := owner.Decision(route, server, meta); err == nil || selected {
				t.Error("feature close preceded routing revocation")
			}
			return nil
		}}}
		nativeRoutingConstructionFailed(ctx, server)
		if calls != 1 {
			t.Fatal("partial feature was not closed exactly once")
		}
	})
	t.Run("cleanup-error-does-not-replace-constructor-error", func(t *testing.T) {
		server := new(Instance)
		ctx, _, _, _ := nativeConstructionOwner(t, server)
		cleanupError := errors.New("synthetic cleanup error")
		originalError := errors.New("synthetic constructor error")
		calls := 0
		server.features = []features.Feature{
			&nativeConstructionFeature{close: func() error { calls++; return cleanupError }},
			&nativeConstructionFeature{close: func() error { calls++; return nil }},
		}
		// Match the constructor hook: cleanup is a side effect, while the exact
		// original init failure remains the authoritative return value.
		returned := func() error { nativeRoutingConstructionFailed(ctx, server); return originalError }()
		if returned != originalError || calls != 2 {
			t.Fatal("cleanup error masked init failure or skipped later features")
		}
	})
	t.Run("nil-partial-state-and-typed-nil-owner", func(t *testing.T) {
		nativeRoutingConstructionFailed(nil, nil)
		ctx := routing.ContextWithNativeRoutingOwner(context.Background(), nil)
		nativeRoutingConstructionFailed(ctx, nil)
		nativeRoutingConstructionFailed(ctx, new(Instance))
		calls := 0
		server := &Instance{features: []features.Feature{&nativeConstructionFeature{close: func() error { calls++; return nil }}}}
		nativeRoutingConstructionFailed(ctx, server)
		if calls != 1 {
			t.Fatal("malformed opt-in seed leaked its partial Core")
		}
	})
}
