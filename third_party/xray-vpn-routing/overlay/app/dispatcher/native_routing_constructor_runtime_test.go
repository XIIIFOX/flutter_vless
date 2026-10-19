package dispatcher_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type nativeConstructorStateKey struct{}

type nativeConstructorState struct {
	key                *core.InboundHandlerConfig
	owner              *routing.NativeRoutingOwner
	feature            *nativeConstructorFeature
	failure            error
	cleanupFailure     error
	closed             atomic.Int32
	started            atomic.Int32
	revokedBeforeClose bool
}

type nativeConstructorFeature struct {
	ctx   context.Context
	state *nativeConstructorState
}

func (*nativeConstructorFeature) Type() interface{} { return (*nativeConstructorFeature)(nil) }
func (f *nativeConstructorFeature) Start() error {
	f.state.started.Add(1)
	return errors.New("constructor fixture must not start")
}
func (f *nativeConstructorFeature) Close() error {
	f.state.closed.Add(1)
	if f.state.owner != nil {
		// Before revocation this exact key/actual instance would bind. Checking
		// here makes owner-before-Core cleanup ordering observable.
		input, err := f.state.owner.BindInput(f.ctx, core.FromContext(f.ctx), f.state.key, new(nativeConstructorHandler))
		f.state.revokedBeforeClose = errors.Is(err, routing.ErrNativeRoutingState)
		if input != nil {
			_ = input.Close()
		}
	}
	return f.state.cleanupFailure
}

type nativeConstructorHandler struct{}

func (*nativeConstructorHandler) Tag() string { return "managed-constructor" }

var nativeConstructorRegistration sync.Once
var nativeConstructorRegistrationError error

// The wrapper protobuf types are unused by the pinned Core's config registry.
// Register once, only from the guarded test; every factory requires this test's
// private context and fixed marker. No constructor runs during package init.
func registerNativeConstructorFixture() error {
	nativeConstructorRegistration.Do(func() {
		nativeConstructorRegistrationError = common.RegisterConfig((*wrapperspb.StringValue)(nil), func(ctx context.Context, value interface{}) (interface{}, error) {
			state, ok := ctx.Value(nativeConstructorStateKey{}).(*nativeConstructorState)
			if !ok || state == nil || value.(*wrapperspb.StringValue).Value != "native-routing-constructor-fixture" {
				return nil, errors.New("invalid constructor fixture")
			}
			state.feature = &nativeConstructorFeature{ctx: ctx, state: state}
			return state.feature, nil
		})
		if nativeConstructorRegistrationError != nil {
			return
		}
		nativeConstructorRegistrationError = common.RegisterConfig((*wrapperspb.BoolValue)(nil), func(ctx context.Context, value interface{}) (interface{}, error) {
			state, ok := ctx.Value(nativeConstructorStateKey{}).(*nativeConstructorState)
			if !ok || state == nil || !value.(*wrapperspb.BoolValue).Value {
				return nil, errors.New("invalid constructor fixture")
			}
			return nil, state.failure
		})
	})
	return nativeConstructorRegistrationError
}

// Actual NewWithContext failure path, deliberately CI-only even though its two
// app factories are inert. Local default validation only compiles this test.
func TestNativeVPNRoutingRuntimeConstruction(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("native VPN routing constructor runtime is CI-only")
	}
	if err := registerNativeConstructorFixture(); err != nil {
		t.Fatal(err)
	}
	for _, optIn := range []bool{false, true} {
		name := "legacy-unseeded"
		if optIn {
			name = "opt-in-partial-core-cleanup"
		}
		t.Run(name, func(t *testing.T) {
			key := &core.InboundHandlerConfig{Tag: "managed-constructor",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: 17893, To: 17893}}}}),
				ProxySettings:    serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"private-constructor": "synthetic-constructor-password"}})}
			state := &nativeConstructorState{key: key, failure: errors.New("synthetic constructor failure"), cleanupFailure: errors.New("synthetic cleanup failure")}
			t.Cleanup(func() {
				if state.feature != nil && state.closed.Load() == 0 {
					_ = state.feature.Close()
				}
			})
			ctx := context.WithValue(context.Background(), nativeConstructorStateKey{}, state)
			if optIn {
				var err error
				state.owner, err = routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: state.key, ManagedTag: state.key.Tag, AuthUser: "private-constructor"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = state.owner.Close() })
				ctx, err = dispatcher.ContextWithNativeVPNRouting(ctx, state.owner, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Fail before essential features, system-dialer initialization or
			// inbound construction. This tests the real early-init cleanup seam.
			configuration := &core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(wrapperspb.String("native-routing-constructor-fixture")),
				serial.ToTypedMessage(wrapperspb.Bool(true)),
			}}
			instance, err := core.NewWithContext(ctx, configuration)
			if instance != nil {
				_ = instance.Close()
			}
			if instance != nil || err != state.failure || state.feature == nil || state.started.Load() != 0 {
				t.Fatal("constructor failure, original error or no-Start contract changed")
			}
			if optIn {
				if state.closed.Load() != 1 || !state.revokedBeforeClose {
					t.Fatal("partial Core was not closed once after owner revocation")
				}
			} else {
				if state.closed.Load() != 0 {
					t.Fatal("legacy unseeded constructor behavior changed")
				}
				// The legacy constructor returned no instance. Its only resource
				// here is our retained inert fake, which the fixture retires itself.
				_ = state.feature.Close()
			}
		})
	}
}
