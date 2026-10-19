package dispatcher_test

import (
	"bytes"
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"testing"
)

type nativeMuxHandler struct{}

func (*nativeMuxHandler) Tag() string { return "managed" }

func TestNativeVPNRoutingMuxSessionRelease(t *testing.T) {
	// Exercise the actual patched SessionManager publication/Close seam using
	// inert buffers. No client worker, Core instance or transport is started.
	key := &core.InboundHandlerConfig{Tag: "managed"}
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: key, ManagedTag: "managed", AuthUser: "private"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	seed := routing.ContextWithNativeRoutingOwner(context.Background(), owner)
	instance, handler := new(core.Instance), new(nativeMuxHandler)
	input, err := owner.BindInput(seed, instance, key, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Seal(instance); err != nil {
		t.Fatal(err)
	}
	meta := routing.NativeRoutingMetadata{Conn: new(struct{ n int }), Tag: "managed", User: "private"}
	control, end, err := input.Begin(seed, instance, handler, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	ctx, outerRelease, err := owner.BeginRoute(control, instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer outerRelease()
	retained, err := routing.RetainNativeRoutingRoute(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manager := mux.NewSessionManager()
	defer manager.Close()
	s := manager.Allocate(&mux.ClientStrategy{}, buf.NewReader(bytes.NewReader(nil)), buf.Discard, retained)
	if s == nil {
		retained()
		t.Fatal("inert session not allocated")
	}
	outerRelease()
	if _, granted, err := owner.Decision(ctx, instance, meta); err != nil || !granted || ctx.Err() != nil {
		t.Fatal("async session lost route at dispatch return")
	}
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("actual mux session Close failed to release final route reference")
	}
	if _, _, err := owner.Decision(ctx, instance, meta); err == nil {
		t.Fatal("closed mux route retained authority")
	}
}
