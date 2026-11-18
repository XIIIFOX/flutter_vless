//go:build flutter_vless_balancer_diagnostics

package XRay

import (
	"context"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/proto"
)

func BalancerDiagnosticsCapability() int64 { return 1 }

// StartBalancerDiagnosticsPrivate starts the same private runtime with an
// in-memory selection history scoped to the provider-owned SOCKS inbound.
// An empty specification selects the ordinary private startup path.
func StartBalancerDiagnosticsPrivate(config, spec []byte, managedInbound string, maxLines int64, logger Logger) error {
	return startBalancerDiagnostics(config, spec, managedInbound, maxLines, logger, true)
}

// StartCLIBalancerDiagnosticsPrivate accepts the unique generated private
// inbound wherever the native launcher inserted it. Android may append it
// after the caller's inbounds.
func StartCLIBalancerDiagnosticsPrivate(config, spec []byte, managedInbound string, maxLines int64, logger Logger) error {
	return startBalancerDiagnostics(config, spec, managedInbound, maxLines, logger, false)
}

func startBalancerDiagnostics(config, spec []byte, managedInbound string, maxLines int64, logger Logger, firstOnly bool) error {
	var configure configureBalancerDiagnostics
	if managedInbound != "" && maxLines >= 1 && maxLines <= 300 {
		configure = func(ctx context.Context, config *core.Config) (context.Context, *balancerDiagnostics) {
			return newBalancerDiagnostics(ctx, config, managedInbound, int(maxLines), firstOnly)
		}
	}
	if len(spec) == 0 {
		return startPrivate(config, logger, configure)
	}
	return startRoutingPrivate(config, spec, logger, configure)
}

// ReadBalancerDiagnostics returns recent sequence,group,node rows, oldest
// first, newline-delimited. The numeric aliases are 1-based config positions.
// There are no rows outside the active, observed runtime.
func ReadBalancerDiagnostics() string {
	coreState.RLock()
	defer coreState.RUnlock()
	if coreBalancerDiagnostics == nil {
		return ""
	}
	return coreBalancerDiagnostics.snapshot()
}

// DisableBalancerDiagnostics clears the active history permanently for this
// Core instance, including the sink still held by the dispatcher.
func DisableBalancerDiagnostics() {
	coreState.RLock()
	defer coreState.RUnlock()
	if coreBalancerDiagnostics != nil {
		coreBalancerDiagnostics.disable()
	}
}

func newBalancerDiagnostics(ctx context.Context, config *core.Config, inboundTag string, maxLines int, firstOnly bool) (context.Context, *balancerDiagnostics) {
	if !isBalancerDiagnosticsInbound(config, inboundTag, firstOnly) {
		return ctx, nil
	}
	groups := configuredBalancerOrdinals(config)
	if len(groups) == 0 {
		return ctx, nil
	}
	nodes := make(map[string]int, len(config.Outbound))
	for index, outbound := range config.Outbound {
		if tag := outbound.GetTag(); tag != "" {
			nodes[tag] = index + 1
		}
	}
	history := &balancerDiagnostics{rows: make([]balancerSelection, maxLines)}
	scoped := dispatcher.ContextWithBalancerObserver(ctx, inboundTag, func(groupTag, outboundTag string) {
		group, node := groups[groupTag], nodes[outboundTag]
		if group > 0 && node > 0 {
			history.record(group, node)
		}
	})
	return scoped, history
}

func isBalancerDiagnosticsInbound(config *core.Config, tag string, firstOnly bool) bool {
	var inbound *core.InboundHandlerConfig
	for index, candidate := range config.Inbound {
		if candidate.GetTag() != tag {
			continue
		}
		if inbound != nil || (firstOnly && index != 0) {
			return false
		}
		inbound = candidate
	}
	if inbound.GetProxySettings() == nil {
		return false
	}
	settings, err := inbound.ProxySettings.GetInstance()
	if err != nil {
		return false
	}
	proxy, ok := settings.(*socks.ServerConfig)
	if !ok || len(proxy.Accounts) != 1 {
		return false
	}
	for user := range proxy.Accounts {
		return nativeRoutingPrivateInput(inbound, tag, user)
	}
	return false
}

func configuredBalancerOrdinals(config *core.Config) map[string]int {
	configName := string(proto.MessageName(&router.Config{}))
	for _, app := range config.App {
		if app.GetType() != configName {
			continue
		}
		settings, err := app.GetInstance()
		if err != nil {
			return nil
		}
		if routerConfig, ok := settings.(*router.Config); ok {
			groups := make(map[string]int, len(routerConfig.BalancingRule))
			for index, group := range routerConfig.BalancingRule {
				groups[group.GetTag()] = index + 1
			}
			return groups
		}
	}
	return nil
}
