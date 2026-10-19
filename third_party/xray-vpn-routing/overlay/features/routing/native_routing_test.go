package routing_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/proto"
)

// These tests construct protobuf configuration values and opaque identities
// only. They never construct a Core instance, handler, socket or listener.
type nativeIdentity struct{ id int }
type nativeHandler struct{ tag string }

func (h *nativeHandler) Tag() string { return h.tag }

type nativeFixture struct {
	owner    *routing.NativeRoutingOwner
	input    *routing.NativeRoutingInput
	ctx      context.Context
	key      *core.InboundHandlerConfig
	instance *nativeIdentity
	handler  *nativeHandler
	policy   routing.NativeRoutingPolicy
}

func nativePolicy() routing.NativeRoutingPolicy {
	return routing.NativeRoutingPolicy{
		Key: &core.InboundHandlerConfig{Tag: "managed", ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
			AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"private-user": "synthetic-password"}, UdpEnabled: true,
		})},
		SourceIndex: 3, ManagedTag: "managed", AliasEnabled: true, InboundAlias: "caller",
		DefaultOutboundTag: "selected-default", AuthUser: "private-user",
	}
}

func newNativeFixture(t *testing.T, modify func(*routing.NativeRoutingPolicy)) *nativeFixture {
	t.Helper()
	policy := nativePolicy()
	if modify != nil {
		modify(&policy)
	}
	owner, err := routing.NewNativeRoutingOwner(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	f := &nativeFixture{owner: owner, key: policy.Key.(*core.InboundHandlerConfig), policy: policy,
		instance: &nativeIdentity{1}, handler: &nativeHandler{tag: policy.ManagedTag}}
	f.ctx = routing.ContextWithNativeRoutingOwner(context.Background(), owner)
	f.input, err = owner.BindInput(f.ctx, f.instance, f.key, f.handler)
	if err != nil || f.input == nil {
		t.Fatalf("bind: %v", err)
	}
	if err := owner.Seal(f.instance); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *nativeFixture) begin(t *testing.T) (context.Context, routing.NativeRoutingMetadata, func()) {
	t.Helper()
	meta := routing.NativeRoutingMetadata{Conn: &nativeIdentity{2}, Tag: f.policy.ManagedTag}
	ctx, end, err := f.input.Begin(f.ctx, f.instance, f.handler, meta)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	meta.Name, meta.User = "socks", f.policy.AuthUser
	return ctx, meta, end
}

func (f *nativeFixture) route(t *testing.T) (context.Context, routing.NativeRoutingMetadata, func()) {
	t.Helper()
	control, meta, _ := f.begin(t)
	ctx, end, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	return ctx, meta, end
}

func TestNativeRoutingPolicyBinding(t *testing.T) {
	t.Run("immutable-policy-and-exact-construction", func(t *testing.T) {
		policy := nativePolicy()
		key := policy.Key.(*core.InboundHandlerConfig)
		owner, err := routing.NewNativeRoutingOwner(policy)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		policy.InboundAlias, policy.AuthUser, policy.DefaultOutboundTag = "changed", "changed", "changed"
		instance, handler := &nativeIdentity{1}, &nativeHandler{tag: "managed"}
		ctx := routing.ContextWithNativeRoutingOwner(context.Background(), owner)
		foreign := proto.Clone(key).(*core.InboundHandlerConfig)
		if input, err := owner.BindInput(ctx, instance, foreign, handler); err != nil || input != nil {
			t.Fatal("same-tag foreign config acquired capability or changed ordinary construction")
		}
		input, err := owner.BindInput(ctx, instance, key, handler)
		if err != nil || input == nil {
			t.Fatal(err)
		}
		meta := routing.NativeRoutingMetadata{Conn: &nativeIdentity{2}, Tag: "managed", Name: "socks", User: "private-user"}
		if _, _, err := input.Begin(ctx, instance, handler, meta); err == nil {
			t.Fatal("unsealed input admitted a control")
		}
		if _, err := owner.BindInput(ctx, instance, key, handler); err == nil {
			t.Fatal("selected key bound twice")
		}
		if err := owner.Seal(&nativeIdentity{1}); err == nil {
			t.Fatal("foreign instance sealed owner")
		}
		if err := owner.Seal(instance); err != nil {
			t.Fatal(err)
		}
		control, end, err := input.Begin(ctx, instance, handler, meta)
		if err != nil {
			t.Fatal(err)
		}
		defer end()
		route, release, err := owner.BeginRoute(control, instance, meta)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		decision, selected, err := owner.Decision(route, instance, meta)
		if err != nil || !selected || decision.InboundAlias != "caller" || decision.DefaultOutboundTag != "selected-default" {
			t.Fatalf("mutable caller policy leaked: %#v %v %v", decision, selected, err)
		}
	})
	t.Run("configuration-mutation-refused", func(t *testing.T) {
		for _, afterBind := range []bool{false, true} {
			policy := nativePolicy()
			owner, err := routing.NewNativeRoutingOwner(policy)
			if err != nil {
				t.Fatal(err)
			}
			ctx := routing.ContextWithNativeRoutingOwner(context.Background(), owner)
			instance, handler := &nativeIdentity{1}, &nativeHandler{tag: "managed"}
			if afterBind {
				if _, err := owner.BindInput(ctx, instance, policy.Key, handler); err != nil {
					t.Fatal(err)
				}
			}
			policy.Key.(*core.InboundHandlerConfig).ProxySettings.Value[0] ^= 1
			if afterBind {
				if err := owner.Seal(instance); err == nil {
					t.Fatal("mutated compiled blueprint sealed")
				}
			} else if _, err := owner.BindInput(ctx, instance, policy.Key, handler); err == nil {
				t.Fatal("mutated compiled blueprint bound")
			}
			_ = owner.Close()
		}
	})
	t.Run("invalid-policy-and-context", func(t *testing.T) {
		for _, modify := range []func(*routing.NativeRoutingPolicy){
			func(p *routing.NativeRoutingPolicy) { p.Key = nil },
			func(p *routing.NativeRoutingPolicy) { p.Key = (*core.InboundHandlerConfig)(nil) },
			func(p *routing.NativeRoutingPolicy) { p.Key = &core.OutboundHandlerConfig{Tag: "managed"} },
			func(p *routing.NativeRoutingPolicy) { p.ManagedTag = "foreign" },
			func(p *routing.NativeRoutingPolicy) { p.AuthUser = "" },
			func(p *routing.NativeRoutingPolicy) { p.MaxFlows = -1 },
		} {
			p := nativePolicy()
			modify(&p)
			if _, err := routing.NewNativeRoutingOwner(p); err == nil {
				t.Fatal("invalid policy accepted")
			}
		}
		if _, ok := routing.NativeRoutingOwnerFromContext(context.Background()); ok {
			t.Fatal("absent owner reported present")
		}
		if owner, ok := routing.NativeRoutingOwnerFromContext(routing.ContextWithNativeRoutingOwner(context.Background(), nil)); !ok || owner != nil {
			t.Fatal("typed nil owner indistinguishable from absence")
		}
	})
}

func TestNativeRoutingFlowIdentity(t *testing.T) {
	f := newNativeFixture(t, nil)
	control, meta, _ := f.begin(t)
	preauth := meta
	preauth.User = ""
	if _, _, err := f.owner.BeginRoute(control, f.instance, preauth); err == nil {
		t.Fatal("unauthenticated control acquired route")
	}
	if _, selected, err := f.owner.Decision(control, f.instance, meta); err == nil || selected {
		t.Fatal("control acquired decision without logical route lifetime")
	}
	route, end, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	decision, selected, err := f.owner.Decision(route, f.instance, meta)
	if err != nil || !selected || !decision.AliasEnabled || decision.InboundAlias != "caller" {
		t.Fatal("legitimate authenticated metadata copy refused")
	}
	decision.InboundAlias = "mutated-result"
	copyMeta := meta // Equivalent to SOCKS UDP's shallow Inbound copy.
	copyMeta.Name = "copied-protocol-metadata"
	if again, selected, err := f.owner.Decision(route, f.instance, copyMeta); err != nil || !selected || again.InboundAlias != "caller" {
		t.Fatal("decision data became authority or protocol metadata was hardcoded")
	}
	for _, changed := range []routing.NativeRoutingMetadata{
		{Conn: &nativeIdentity{2}, Tag: meta.Tag, Name: meta.Name, User: meta.User},
		{Conn: meta.Conn, Tag: meta.Tag, Name: meta.Name, User: "foreign-user"},
	} {
		if _, selected, err := f.owner.Decision(route, f.instance, changed); err == nil || selected {
			t.Fatal("borrowed capsule or foreign authentication admitted")
		}
	}
	if _, _, err := f.owner.Decision(route, &nativeIdentity{1}, meta); err == nil {
		t.Fatal("foreign instance admitted")
	}
	if _, _, err := f.input.Begin(f.ctx, f.instance, &nativeHandler{tag: "managed"}, meta); err == nil {
		t.Fatal("replacement same-tag handler acquired flow")
	}
	if _, _, err := f.input.Begin(context.Background(), f.instance, f.handler, meta); err == nil {
		t.Fatal("missing construction owner admitted")
	}
	if unchanged, release, err := f.owner.BeginRoute(f.ctx, f.instance, meta); err != nil || unchanged != f.ctx {
		t.Fatal("unselected context changed")
	} else {
		release()
		if _, selected, err := f.owner.Decision(unchanged, f.instance, meta); err != nil || selected {
			t.Fatal("tag alone acquired policy")
		}
	}
	foreignMeta := meta
	foreignMeta.Tag = "caller"
	if _, selected, err := f.owner.Decision(context.Background(), f.instance, foreignMeta); err != nil || selected {
		t.Fatal("ordinary source context changed")
	}
}

func TestNativeRoutingLogicalHandoff(t *testing.T) {
	f := newNativeFixture(t, nil)
	control, meta, _ := f.begin(t)
	first, end, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	second, secondEnd, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer secondEnd()
	alias := meta
	alias.Tag, alias.User = "caller-loopback", "changed-after-handoff"
	inherited, inheritedEnd, err := f.owner.BeginRoute(first, f.instance, alias)
	if err != nil {
		t.Fatal(err)
	}
	inheritedEnd() // Recursive dispatch cannot retire its parent's token.
	if _, selected, err := f.owner.Decision(inherited, f.instance, meta); err != nil || selected {
		t.Fatal("handed-off route reacquired policy when tag changed back")
	}
	if _, selected, err := f.owner.Decision(second, f.instance, meta); err != nil || !selected {
		t.Fatal("one UDP logical route disabled its independent sibling")
	}
	if _, selected, err := f.owner.Decision(first, f.instance, alias); err != nil || selected {
		t.Fatal("legitimate loopback was rejected instead of legacy routing")
	}
	end()
	if _, _, err := f.owner.Decision(first, f.instance, meta); err == nil {
		t.Fatal("ended route accepted")
	}
}

func TestNativeRoutingLifetime(t *testing.T) {
	for _, stopInput := range []bool{false, true} {
		f := newNativeFixture(t, nil)
		ctx, meta, _ := f.route(t)
		if stopInput {
			if err := f.input.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err := f.owner.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("revocation did not synchronously cancel flow")
		}
		if _, _, err := f.owner.Decision(ctx, f.instance, meta); err == nil {
			t.Fatal("closed owner published decision")
		}
		if _, _, err := f.input.Begin(f.ctx, f.instance, f.handler, meta); err == nil {
			t.Fatal("closed input readmitted control")
		}
		if _, err := f.owner.BindInput(f.ctx, f.instance, f.key, &nativeHandler{tag: "managed"}); err == nil {
			t.Fatal("replacement handler reacquired retired key")
		}
		if unchanged, release, err := f.owner.BeginRoute(f.ctx, f.instance, meta); err != nil || unchanged != f.ctx {
			t.Fatal("closing selected input changed an imported handler")
		} else {
			release()
			if _, selected, err := f.owner.Decision(unchanged, f.instance, meta); err != nil || selected {
				t.Fatal("imported handler inherited closed policy")
			}
		}
		_ = f.input.Close()
		_ = f.owner.Close()
	}
	f := newNativeFixture(t, nil)
	parent, cancel := context.WithCancel(f.ctx)
	meta := routing.NativeRoutingMetadata{Conn: &nativeIdentity{3}, Tag: "managed", User: "private-user"}
	control, end, err := f.input.Begin(parent, f.instance, f.handler, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	route, release, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cancel()
	if _, _, err := f.owner.Decision(route, f.instance, meta); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled operation published decision: %v", err)
	}
	if _, _, err := f.owner.BeginRoute(control, f.instance, meta); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled parent created child route")
	}
}

func TestNativeRoutingBoundsAndEmptyAlias(t *testing.T) {
	f := newNativeFixture(t, func(p *routing.NativeRoutingPolicy) { p.MaxFlows, p.InboundAlias = 1, "" })
	control, meta, end := f.begin(t)
	if _, _, err := f.input.Begin(f.ctx, f.instance, f.handler, meta); err == nil {
		t.Fatal("positive control bound ignored")
	}
	route, release, err := f.owner.BeginRoute(control, f.instance, meta)
	if err != nil {
		t.Fatal(err)
	}
	if decision, selected, err := f.owner.Decision(route, f.instance, meta); err != nil || !selected || !decision.AliasEnabled || decision.InboundAlias != "" {
		t.Fatal("explicit empty alias collapsed into disabled alias")
	}
	if _, _, err := f.owner.BeginRoute(control, f.instance, meta); err == nil {
		t.Fatal("positive route bound ignored")
	}
	release()
	if _, nextEnd, err := f.owner.BeginRoute(control, f.instance, meta); err != nil {
		t.Fatal("released route slot retained")
	} else {
		nextEnd()
	}
	end()
	if _, nextEnd, err := f.input.Begin(f.ctx, f.instance, f.handler, meta); err != nil {
		t.Fatal("released control slot retained")
	} else {
		nextEnd()
	}
	unlimited := newNativeFixture(t, func(p *routing.NativeRoutingPolicy) { p.AliasEnabled = false })
	for i := 0; i < 16; i++ {
		ctx, metadata, _ := unlimited.route(t)
		if decision, selected, err := unlimited.owner.Decision(ctx, unlimited.instance, metadata); err != nil || !selected || decision.AliasEnabled {
			t.Fatal("zero bound was not unlimited or alias unexpectedly enabled")
		}
	}
}

func TestNativeRoutingConcurrentRevoke(t *testing.T) {
	f := newNativeFixture(t, nil)
	ctx, meta, end := f.route(t)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 32; j++ {
				_, _, _ = f.owner.Decision(ctx, f.instance, meta)
			}
		}()
	}
	_ = f.owner.Close()
	end()
	workers.Wait()
	if _, selected, err := f.owner.Decision(ctx, f.instance, meta); err == nil || selected {
		t.Fatal("post-revoke result published")
	}
}

func TestNativeRoutingAsyncRetain(t *testing.T) {
	t.Run("async-worker-outlives-dispatch-return", func(t *testing.T) {
		f := newNativeFixture(t, nil)
		ctx, meta, end := f.route(t)
		workerEnd, err := routing.RetainNativeRoutingRoute(ctx)
		if err != nil {
			t.Fatal(err)
		}
		end()
		end() // The outer release cannot consume an asynchronous worker's ref.
		if ctx.Err() != nil {
			t.Fatal("ordinary Dispatch return canceled a retained mux worker")
		}
		if _, selected, err := f.owner.Decision(ctx, f.instance, meta); err != nil || !selected {
			t.Fatal("retained asynchronous route lost its binding")
		}
		workerEnd()
		workerEnd()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("last worker release did not retire route")
		}
		if _, selected, err := f.owner.Decision(ctx, f.instance, meta); err == nil || selected {
			t.Fatal("finished asynchronous route retained authority")
		}
	})
	t.Run("revocation-wins-over-held-reference", func(t *testing.T) {
		f := newNativeFixture(t, nil)
		ctx, meta, end := f.route(t)
		workerEnd, err := routing.RetainNativeRoutingRoute(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.input.Close(); err != nil {
			t.Fatal(err)
		}
		if ctx.Err() != context.Canceled {
			t.Fatal("held mux ref delayed owner revocation")
		}
		if _, selected, err := f.owner.Decision(ctx, f.instance, meta); err == nil || selected {
			t.Fatal("held ref overrode revocation")
		}
		if _, err := routing.RetainNativeRoutingRoute(ctx); err == nil {
			t.Fatal("closed route accepted more workers")
		}
		end()
		workerEnd()
	})
	t.Run("bounds-count-routes-not-worker-refs", func(t *testing.T) {
		f := newNativeFixture(t, func(p *routing.NativeRoutingPolicy) { p.MaxFlows = 1 })
		control, meta, _ := f.begin(t)
		ctx, end, err := f.owner.BeginRoute(control, f.instance, meta)
		if err != nil {
			t.Fatal(err)
		}
		first, err := routing.RetainNativeRoutingRoute(ctx)
		if err != nil {
			t.Fatal("worker ref incorrectly consumed another route slot")
		}
		second, err := routing.RetainNativeRoutingRoute(ctx)
		if err != nil {
			t.Fatal(err)
		}
		end()
		first()
		if _, _, err := f.owner.BeginRoute(control, f.instance, meta); !errors.Is(err, routing.ErrNativeRoutingLimit) {
			t.Fatal("live asynchronous route no longer counted toward bound")
		}
		second()
		if _, release, err := f.owner.BeginRoute(control, f.instance, meta); err != nil {
			t.Fatal("last worker release did not free route slot")
		} else {
			release()
		}
	})
	t.Run("legacy-foreign-and-handoff", func(t *testing.T) {
		if end, err := routing.RetainNativeRoutingRoute(context.Background()); err != nil {
			t.Fatal("ordinary caller route changed")
		} else {
			end()
		}
		if _, err := routing.RetainNativeRoutingRoute(routing.ContextWithNativeRoutingOwner(context.Background(), nil)); err == nil {
			t.Fatal("typed nil native owner silently opted out")
		}
		f := newNativeFixture(t, nil)
		control, meta, _ := f.begin(t)
		if _, err := routing.RetainNativeRoutingRoute(control); err == nil {
			t.Fatal("control minted a route by retaining")
		}
		ctx, end, err := f.owner.BeginRoute(control, f.instance, meta)
		if err != nil {
			t.Fatal(err)
		}
		other := newNativeFixture(t, nil)
		if _, err := routing.RetainNativeRoutingRoute(routing.ContextWithNativeRoutingOwner(ctx, other.owner)); err == nil {
			t.Fatal("foreign owner retained a borrowed route")
		}
		meta.Tag = "caller-loopback"
		if _, selected, err := f.owner.Decision(ctx, f.instance, meta); err != nil || selected {
			t.Fatal("loopback did not hand off")
		}
		workerEnd, err := routing.RetainNativeRoutingRoute(ctx)
		if err != nil {
			t.Fatal("legitimate loopback worker lost lifetime ownership")
		}
		end()
		if ctx.Err() != nil {
			t.Fatal("handed-off asynchronous worker canceled early")
		}
		workerEnd()
		_ = f.owner.Close()
		if release, err := routing.RetainNativeRoutingRoute(f.ctx); err != nil {
			t.Fatal("closed owner broke imported context")
		} else {
			release()
		}
	})
}
