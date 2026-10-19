package dispatcher

import (
	"context"
	"errors"
	"maps"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

type nativeRoutingPlanKey struct{}

type nativeRoutingGuard struct {
	condition    router.Condition
	tag, ruleTag string
}

type nativeRoutingPlan struct {
	owner  *routing.NativeRoutingOwner
	guards []nativeRoutingGuard
}

// ContextWithNativeVPNRouting is a trusted native construction API, not a JSON
// option. The owner identifies the exact compiled private SOCKS input. Guards
// are generated native rules, kept outside the caller's live Routing API.
// Only literal, inbound-scoped guards are admitted; caller rules are not copied.
func ContextWithNativeVPNRouting(ctx context.Context, owner *routing.NativeRoutingOwner, guards []*router.RoutingRule) (context.Context, error) {
	if ctx == nil || owner == nil || ctx.Err() != nil {
		return nil, routing.ErrNativeRoutingPolicy
	}
	if _, exists := routing.NativeRoutingOwnerFromContext(ctx); exists {
		return nil, routing.ErrNativeRoutingScope
	}
	plan := &nativeRoutingPlan{owner: owner}
	for _, source := range guards {
		if source == nil || source.GetTag() == "" || source.GetBalancingTag() != "" || source.Webhook != nil || len(source.InboundTag) == 0 {
			return nil, routing.ErrNativeRoutingPolicy
		}
		for _, tag := range source.InboundTag {
			if tag == "" {
				return nil, routing.ErrNativeRoutingPolicy
			}
		}
		rule := proto.Clone(source).(*router.RoutingRule)
		condition, err := rule.BuildCondition()
		if err != nil {
			return nil, err
		}
		plan.guards = append(plan.guards, nativeRoutingGuard{condition: condition, tag: rule.GetTag(), ruleTag: rule.RuleTag})
	}
	ctx = routing.ContextWithNativeRoutingOwner(ctx, owner)
	return context.WithValue(ctx, nativeRoutingPlanKey{}, plan), nil
}

type nativeRoutingDispatcher struct {
	plan     *nativeRoutingPlan
	instance *core.Instance
}

func (d *DefaultDispatcher) bindNativeVPNRouting(ctx context.Context) error {
	owner, seeded := routing.NativeRoutingOwnerFromContext(ctx)
	plan, planned := ctx.Value(nativeRoutingPlanKey{}).(*nativeRoutingPlan)
	if !seeded && !planned {
		return nil
	}
	if !seeded || !planned || owner == nil || plan == nil || plan.owner != owner || core.FromContext(ctx) == nil {
		return routing.ErrNativeRoutingScope
	}
	d.nativeRouting = &nativeRoutingDispatcher{plan: plan, instance: core.FromContext(ctx)}
	return nil
}

func nativeRoutingMetadata(ctx context.Context) routing.NativeRoutingMetadata {
	in := session.InboundFromContext(ctx)
	if in == nil {
		return routing.NativeRoutingMetadata{}
	}
	meta := routing.NativeRoutingMetadata{Conn: in.Conn, Tag: in.Tag, Name: in.Name}
	if in.User != nil {
		meta.User = in.User.Email
	}
	return meta
}

func consumeNativeForcedOutbound(ctx context.Context) context.Context {
	content := session.ContentFromContext(ctx)
	if content == nil || content.Attribute("forcedOutboundTag") == "" {
		return ctx
	}
	// A UDP sibling may share Content. Consume only this ray's detour; preserve
	// protocol, sniffing, DNS flags and all unrelated caller attributes.
	copy := *content
	copy.Attributes = maps.Clone(content.Attributes)
	copy.SetAttribute("forcedOutboundTag", "")
	return session.ContextWithContent(ctx, &copy)
}

func (d *DefaultDispatcher) nativeStart() error {
	if d.nativeRouting == nil {
		return nil
	}
	return d.nativeRouting.plan.owner.Seal(d.nativeRouting.instance)
}

func (d *DefaultDispatcher) nativeClose() error {
	if d.nativeRouting == nil {
		return nil
	}
	return d.nativeRouting.plan.owner.Close()
}

func interruptNativeRouting(link *transport.Link) {
	common.Close(link.Writer)
	common.Interrupt(link.Reader)
}

// Lifetime starts after sniff/auth and ends when the actual outbound handler
// returns. Dispatch itself returns its link before routing, so it cannot own it.
func (d *DefaultDispatcher) nativeBeginRoute(ctx context.Context, link *transport.Link) (context.Context, func(), error) {
	if d.nativeRouting == nil {
		return ctx, func() {}, nil
	}
	n := d.nativeRouting
	routed, release, err := n.plan.owner.BeginRoute(ctx, core.FromContext(ctx), nativeRoutingMetadata(ctx))
	if err != nil {
		return nil, nil, err
	}
	_, granted, err := d.nativeDecision(routed)
	if err != nil {
		release()
		return nil, nil, err
	}
	if granted {
		// Mux may retain a ray after Handler.Dispatch returns. Keep interruption
		// attached to its true lifetime, not that asynchronous return. Capture
		// endpoints before outbound handlers install their own link wrappers.
		reader, writer := link.Reader, link.Writer
		context.AfterFunc(routed, func() { common.Close(writer); common.Interrupt(reader) })
	}
	return routed, release, nil
}

type nativeRoutingAlias struct {
	routing.Context
	tag string
}

func (c nativeRoutingAlias) GetInboundTag() string { return c.tag }

type nativeRoutingRoute struct {
	routing.Context
	tag, ruleTag string
}

func (r nativeRoutingRoute) GetOutboundTag() string         { return r.tag }
func (r nativeRoutingRoute) GetOutboundGroupTags() []string { return nil }
func (r nativeRoutingRoute) GetRuleTag() string             { return r.ruleTag }

func (d *DefaultDispatcher) nativeDecision(ctx context.Context) (routing.NativeRoutingDecision, bool, error) {
	if d.nativeRouting == nil {
		return routing.NativeRoutingDecision{}, false, nil
	}
	n := d.nativeRouting
	return n.plan.owner.Decision(ctx, core.FromContext(ctx), nativeRoutingMetadata(ctx))
}

// A false handled value preserves the original Core selection for imported
// flows. The physical context goes to private guards before forced detours; only
// the complete, live caller router receives the optional inbound-tag view.
func (d *DefaultDispatcher) nativePickRoute(ctx context.Context, physical routing.Context) (route routing.Route, kind int, handled bool, err error) {
	if d.nativeRouting == nil {
		return nil, 0, false, nil
	}
	decision, granted, err := d.nativeDecision(ctx)
	if err != nil {
		return nil, 0, true, err
	}
	defer func() {
		if !handled || err != nil {
			return
		}
		_, stillGranted, checkErr := d.nativeDecision(ctx)
		if checkErr != nil {
			route, err = nil, checkErr
		} else if granted && !stillGranted {
			route, err = nil, routing.ErrNativeRoutingScope
		}
	}()
	for _, guard := range d.nativeRouting.plan.guards {
		if guard.condition.Apply(physical) {
			return nativeRoutingRoute{Context: physical, tag: guard.tag, ruleTag: guard.ruleTag}, 2, true, nil
		}
	}
	if !granted {
		return nil, 0, false, nil
	}
	if forced := session.GetForcedOutboundTagFromContext(ctx); forced != "" {
		return nativeRoutingRoute{Context: physical, tag: forced}, 1, true, nil
	}
	caller := physical
	if decision.AliasEnabled {
		caller = nativeRoutingAlias{Context: physical, tag: decision.InboundAlias}
	}
	err = common.ErrNoClue
	if d.router != nil {
		route, err = d.router.PickRoute(caller)
	}
	if err == nil {
		if route == nil {
			return nil, 0, true, errors.New("native routing returned no route")
		}
		return route, 2, true, nil
	}
	// Match Core's exact sentinel semantics. Other errors must not be converted
	// into a selected default or fallback to the first outbound.
	if err != common.ErrNoClue {
		return nil, 0, true, err
	}
	if decision.DefaultOutboundTag != "" {
		return nativeRoutingRoute{Context: caller, tag: decision.DefaultOutboundTag}, 0, true, nil
	}
	return nil, 0, true, nil
}
