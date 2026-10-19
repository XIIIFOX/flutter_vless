package routing

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// NativeRoutingPolicy is supplied by the native session owner, never decoded
// from caller JSON. Key is the exact compiled private inbound configuration
// passed to the constructor. SourceIndex is diagnostic data, not authority.
// MaxFlows == 0 is unlimited; a positive value separately bounds live controls
// and logical routes. Ordinary Core concurrency is not capped by default.
type NativeRoutingPolicy struct {
	Key                proto.Message
	SourceIndex        int
	ManagedTag         string
	AliasEnabled       bool
	InboundAlias       string
	DefaultOutboundTag string
	AuthUser           string
	MaxFlows           int
}

// NativeRoutingMetadata is copied from the current session by the Core hooks.
// Conn is the actual control-connection identity. It is never read or closed by
// this package. A SOCKS UDP metadata copy may differ in all other pointer fields
// while retaining this connection and the inherited private context capsule.
type NativeRoutingMetadata struct {
	Conn any
	Tag  string
	Name string
	User string
}

// NativeRoutingDecision is data, not an authorization capability. The caller
// must recheck Decision after blocking router work and before publishing an
// alias/default result. AliasEnabled distinguishes no alias from an empty tag.
type NativeRoutingDecision struct {
	AliasEnabled       bool
	InboundAlias       string
	DefaultOutboundTag string
}

var (
	ErrNativeRoutingPolicy = errors.New("invalid native routing policy")
	ErrNativeRoutingScope  = errors.New("native routing scope mismatch")
	ErrNativeRoutingState  = errors.New("native routing state unavailable")
	ErrNativeRoutingLimit  = errors.New("native routing admission limit")
)

type nativeRoutingContextKey uint8

const (
	nativeRoutingOwnerKey nativeRoutingContextKey = iota
	nativeRoutingControlKey
	nativeRoutingRouteKey
)

// NativeRoutingOwner contains only admission and cancellation state. The hooks
// retain all connection/link cleanup ownership; Close does no file/socket IO.
// No Core/session/proxy dependency is introduced into features/routing.
type NativeRoutingOwner struct {
	mu       sync.Mutex
	policy   NativeRoutingPolicy
	snapshot proto.Message
	instance any
	input    *NativeRoutingInput
	sealed   bool
	closed   bool
	controls map[*nativeRoutingControl]struct{}
	routes   map[*nativeRoutingRoute]struct{}
}

type NativeRoutingInput struct {
	owner   *NativeRoutingOwner
	handler any
	closed  bool // guarded by owner.mu
}

type nativeRoutingControl struct {
	input  *NativeRoutingInput
	conn   any
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	routes map[*nativeRoutingRoute]struct{}
}

type nativeRoutingRoute struct {
	control   *nativeRoutingControl
	ctx       context.Context
	cancel    context.CancelFunc
	refs      int
	closed    bool
	handedOff bool
}

func nativeRoutingPointer(value any) bool {
	if value == nil {
		return false
	}
	r := reflect.ValueOf(value)
	return r.Kind() == reflect.Pointer && !r.IsNil()
}

func nativeRoutingSame(a, b any) bool {
	return nativeRoutingPointer(a) && nativeRoutingPointer(b) && reflect.TypeOf(a) == reflect.TypeOf(b) && a == b
}

func nativeRoutingKey(key proto.Message, tag string) bool {
	if !nativeRoutingPointer(key) {
		return false
	}
	m := key.ProtoReflect()
	if m.Descriptor().FullName() != "xray.core.InboundHandlerConfig" {
		return false
	}
	field := m.Descriptor().Fields().ByName("tag")
	return field != nil && field.Kind() == protoreflect.StringKind && m.Get(field).String() == tag
}

func NewNativeRoutingOwner(policy NativeRoutingPolicy) (*NativeRoutingOwner, error) {
	if policy.ManagedTag == "" || policy.AuthUser == "" || policy.MaxFlows < 0 || !nativeRoutingKey(policy.Key, policy.ManagedTag) {
		return nil, ErrNativeRoutingPolicy
	}
	return &NativeRoutingOwner{policy: policy, snapshot: proto.Clone(policy.Key),
		controls: make(map[*nativeRoutingControl]struct{}), routes: make(map[*nativeRoutingRoute]struct{})}, nil
}

func ContextWithNativeRoutingOwner(ctx context.Context, owner *NativeRoutingOwner) context.Context {
	return context.WithValue(ctx, nativeRoutingOwnerKey, owner)
}

// The bool also reports a deliberately installed typed-nil owner; callers must
// fail closed for that malformed seed rather than treating it as opt-out.
func NativeRoutingOwnerFromContext(ctx context.Context) (*NativeRoutingOwner, bool) {
	if ctx == nil {
		return nil, false
	}
	owner, ok := ctx.Value(nativeRoutingOwnerKey).(*NativeRoutingOwner)
	return owner, ok
}

func (o *NativeRoutingOwner) seeded(ctx context.Context) bool {
	owner, ok := NativeRoutingOwnerFromContext(ctx)
	return ok && owner == o && o != nil
}

// BindInput is called only by the actual inbound constructor, with its real
// instance/config/handler identities. Unselected caller handlers remain ordinary
// handlers, including a later API-created handler with an equal tag/config.
func (o *NativeRoutingOwner) BindInput(ctx context.Context, instance any, key proto.Message, handler any) (*NativeRoutingInput, error) {
	if !o.seeded(ctx) || !nativeRoutingPointer(instance) {
		return nil, ErrNativeRoutingScope
	}
	if !nativeRoutingSame(key, o.policy.Key) {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	tagged, ok := handler.(interface{ Tag() string })
	if !nativeRoutingPointer(handler) || !ok || tagged.Tag() != o.policy.ManagedTag {
		return nil, ErrNativeRoutingScope
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.sealed || o.input != nil {
		return nil, ErrNativeRoutingState
	}
	if !proto.Equal(o.policy.Key, o.snapshot) {
		return nil, ErrNativeRoutingPolicy
	}
	o.instance = instance
	o.input = &NativeRoutingInput{owner: o, handler: handler}
	return o.input, nil
}

// Seal ends construction admission before Core.Start. It does not freeze or
// inspect caller routing rules: the real caller router remains live.
func (o *NativeRoutingOwner) Seal(instance any) error {
	if o == nil {
		return ErrNativeRoutingScope
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !nativeRoutingSame(instance, o.instance) {
		return ErrNativeRoutingScope
	}
	if o.closed || o.input == nil || o.input.closed {
		return ErrNativeRoutingState
	}
	if !proto.Equal(o.policy.Key, o.snapshot) {
		return ErrNativeRoutingPolicy
	}
	o.sealed = true
	return nil
}

func nativeRoutingNoop() {}

// ValidateAuthUser checks the actual private SOCKS account during construction.
// It exposes neither credentials nor policy state and grants no flow token.
func (i *NativeRoutingInput) ValidateAuthUser(user string) error {
	if i == nil || i.owner == nil {
		return ErrNativeRoutingScope
	}
	o := i.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || i.closed || o.input != i {
		return ErrNativeRoutingState
	}
	if user == "" || user != o.policy.AuthUser {
		return ErrNativeRoutingPolicy
	}
	return nil
}

func nativeRoutingCapsules(ctx context.Context) (*nativeRoutingControl, *nativeRoutingRoute, error) {
	rawControl, rawRoute := ctx.Value(nativeRoutingControlKey), ctx.Value(nativeRoutingRouteKey)
	control, controlOK := rawControl.(*nativeRoutingControl)
	route, routeOK := rawRoute.(*nativeRoutingRoute)
	if (rawControl != nil && (!controlOK || control == nil)) || (rawRoute != nil && (!routeOK || route == nil)) {
		return nil, nil, ErrNativeRoutingScope
	}
	return control, route, nil
}

// Begin records a control before authentication. It grants no routing decision.
// The inbound hook must release it after proxy.Process actually finishes, and
// close the owned connection when this returned context is canceled.
func (i *NativeRoutingInput) Begin(ctx context.Context, instance, handler any, meta NativeRoutingMetadata) (context.Context, func(), error) {
	if i == nil || i.owner == nil {
		return nil, nil, ErrNativeRoutingScope
	}
	o := i.owner
	if !o.seeded(ctx) || !nativeRoutingSame(handler, i.handler) || !nativeRoutingPointer(meta.Conn) || meta.Tag != o.policy.ManagedTag {
		return nil, nil, ErrNativeRoutingScope
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if ctx.Value(nativeRoutingControlKey) != nil || ctx.Value(nativeRoutingRouteKey) != nil {
		return nil, nil, ErrNativeRoutingScope
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !nativeRoutingSame(instance, o.instance) {
		return nil, nil, ErrNativeRoutingScope
	}
	if o.closed || !o.sealed || i.closed || o.input != i {
		return nil, nil, ErrNativeRoutingState
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if o.policy.MaxFlows > 0 && len(o.controls) >= o.policy.MaxFlows {
		return nil, nil, ErrNativeRoutingLimit
	}
	control := &nativeRoutingControl{input: i, conn: meta.Conn, routes: make(map[*nativeRoutingRoute]struct{})}
	base, cancel := context.WithCancel(ctx)
	control.cancel = cancel
	control.ctx = context.WithValue(base, nativeRoutingControlKey, control)
	o.controls[control] = struct{}{}
	return control.ctx, func() { o.endControl(control) }, nil
}

// validate is called with o.mu held. A changed tag marks only this logical route
// as permanently handed off. It cannot grant privileges again if a loopback
// later restores the managed tag, and cannot poison a UDP sibling's token.
func (o *NativeRoutingOwner) validate(ctx context.Context, instance any, meta NativeRoutingMetadata, control *nativeRoutingControl, route *nativeRoutingRoute) error {
	if !o.seeded(ctx) || !nativeRoutingSame(instance, o.instance) || control == nil || control.input != o.input || !nativeRoutingSame(meta.Conn, control.conn) {
		return ErrNativeRoutingScope
	}
	if o.closed || !o.sealed || o.input == nil || o.input.closed || control.closed {
		return ErrNativeRoutingState
	}
	if _, ok := o.controls[control]; !ok {
		return ErrNativeRoutingScope
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := control.ctx.Err(); err != nil {
		return err
	}
	if route != nil {
		if route.control != control || route.closed {
			return ErrNativeRoutingState
		}
		if _, ok := o.routes[route]; !ok {
			return ErrNativeRoutingScope
		}
		if err := route.ctx.Err(); err != nil {
			return err
		}
		if meta.Tag != o.policy.ManagedTag {
			route.handedOff = true
		}
		if route.handedOff {
			return nil
		}
	}
	if meta.Tag != o.policy.ManagedTag || meta.User != o.policy.AuthUser {
		return ErrNativeRoutingScope
	}
	return nil
}

// BeginRoute belongs at routedDispatch after sniffing, not Dispatch's early
// asynchronous return. End it only when the actual routed handler finishes.
// A recursive dispatch inherits its token and gets a no-op release. A new UDP
// target starting from the control context gets an independent token.
func (o *NativeRoutingOwner) BeginRoute(ctx context.Context, instance any, meta NativeRoutingMetadata) (context.Context, func(), error) {
	if o == nil || ctx == nil {
		return nil, nil, ErrNativeRoutingScope
	}
	control, route, err := nativeRoutingCapsules(ctx)
	if err != nil {
		return nil, nil, err
	}
	if control == nil && route == nil {
		// Imported handlers inherit the construction context too. A tag alone
		// never selects this policy, even after the selected input is closed.
		return ctx, nativeRoutingNoop, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.validate(ctx, instance, meta, control, route); err != nil {
		return nil, nil, err
	}
	if route != nil {
		return ctx, nativeRoutingNoop, nil
	}
	if o.policy.MaxFlows > 0 && len(o.routes) >= o.policy.MaxFlows {
		return nil, nil, ErrNativeRoutingLimit
	}
	base, cancel := context.WithCancel(ctx)
	route = &nativeRoutingRoute{control: control, cancel: cancel, refs: 1}
	route.ctx = context.WithValue(base, nativeRoutingRouteKey, route)
	o.routes[route] = struct{}{}
	control.routes[route] = struct{}{}
	return route.ctx, o.routeRelease(route), nil
}

func (o *NativeRoutingOwner) Decision(ctx context.Context, instance any, meta NativeRoutingMetadata) (NativeRoutingDecision, bool, error) {
	if o == nil || ctx == nil {
		return NativeRoutingDecision{}, false, ErrNativeRoutingScope
	}
	control, route, err := nativeRoutingCapsules(ctx)
	if err != nil {
		return NativeRoutingDecision{}, false, err
	}
	if control == nil && route == nil {
		return NativeRoutingDecision{}, false, nil
	}
	if route == nil {
		return NativeRoutingDecision{}, false, ErrNativeRoutingScope
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.validate(ctx, instance, meta, control, route); err != nil {
		return NativeRoutingDecision{}, false, err
	}
	if route.handedOff {
		return NativeRoutingDecision{}, false, nil
	}
	return NativeRoutingDecision{AliasEnabled: o.policy.AliasEnabled, InboundAlias: o.policy.InboundAlias,
		DefaultOutboundTag: o.policy.DefaultOutboundTag}, true, nil
}

// RetainNativeRoutingRoute transfers a lifetime reference to an asynchronous
// Core worker (for example a mux session). It cannot mint a route or restore an
// alias after handoff. The worker registers the returned release before it
// publishes/starts its session, and releases it on every failure/close path.
func RetainNativeRoutingRoute(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ErrNativeRoutingScope
	}
	o, present := NativeRoutingOwnerFromContext(ctx)
	control, route, err := nativeRoutingCapsules(ctx)
	if err != nil || (present && o == nil) {
		return nil, ErrNativeRoutingScope
	}
	if control == nil && route == nil {
		return nativeRoutingNoop, nil
	}
	if !present || o == nil || control == nil || route == nil {
		return nil, ErrNativeRoutingScope
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if control.input != o.input || route.control != control {
		return nil, ErrNativeRoutingScope
	}
	if o.closed || !o.sealed || o.input == nil || o.input.closed || control.closed || route.closed {
		return nil, ErrNativeRoutingState
	}
	if _, ok := o.controls[control]; !ok {
		return nil, ErrNativeRoutingScope
	}
	if _, ok := o.routes[route]; !ok {
		return nil, ErrNativeRoutingScope
	}
	for _, operation := range []context.Context{ctx, control.ctx, route.ctx} {
		if err := operation.Err(); err != nil {
			return nil, err
		}
	}
	route.refs++
	return o.routeRelease(route), nil
}

func (o *NativeRoutingOwner) routeRelease(route *nativeRoutingRoute) func() {
	var once sync.Once
	return func() { once.Do(func() { o.endRoute(route) }) }
}

func (o *NativeRoutingOwner) endRoute(route *nativeRoutingRoute) {
	o.mu.Lock()
	if route.closed {
		o.mu.Unlock()
		return
	}
	route.refs--
	if route.refs > 0 {
		o.mu.Unlock()
		return
	}
	route.closed = true
	delete(o.routes, route)
	delete(route.control.routes, route)
	o.mu.Unlock()
	route.cancel()
}

func (o *NativeRoutingOwner) retireControl(control *nativeRoutingControl) []context.CancelFunc {
	control.closed = true
	delete(o.controls, control)
	cancels := []context.CancelFunc{control.cancel}
	for route := range control.routes {
		route.closed = true
		route.refs = 0
		delete(o.routes, route)
		cancels = append(cancels, route.cancel)
	}
	clear(control.routes)
	return cancels
}

func (o *NativeRoutingOwner) endControl(control *nativeRoutingControl) {
	o.mu.Lock()
	if control.closed {
		o.mu.Unlock()
		return
	}
	cancels := o.retireControl(control)
	o.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (o *NativeRoutingOwner) close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	if o.input != nil {
		o.input.closed = true
	}
	var cancels []context.CancelFunc
	for control := range o.controls {
		cancels = append(cancels, o.retireControl(control)...)
	}
	o.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return nil
}

// Close synchronously revokes policy admission even if every caller context is
// already canceled. Closing the selected input also retires this session policy
// permanently; API remove/re-add cannot rebind the old compiled key.
func (i *NativeRoutingInput) Close() error {
	if i == nil || i.owner == nil {
		return nil
	}
	return i.owner.close()
}

func (o *NativeRoutingOwner) Close() error {
	if o == nil {
		return nil
	}
	return o.close()
}
