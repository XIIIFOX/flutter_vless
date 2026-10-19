//go:build flutter_vless_vpn_routing

package XRay

import (
	"context"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

// Only builds using the separately pinned optional Core overlay can compile
// this file. Default builds expose the same symbols with capability zero.
func RoutingCapability() int64 { return 1 }

func CheckRoutingPrivate(config, spec []byte) int64 {
	_, code := prepareNativeRouting(config, spec)
	return code
}

func StartRoutingPrivate(config, spec []byte, logger Logger) error {
	runtimeOperation.Lock()
	defer runtimeOperation.Unlock()
	if hasPublishedRuntime() {
		return startupFailure(logger, "active session")
	}
	prepared, code := prepareNativeRouting(config, spec)
	if code != 0 {
		return startupFailure(logger, "routing preparation")
	}
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{
		Key: prepared.key, SourceIndex: prepared.managedIndex, ManagedTag: prepared.managedTag,
		AuthUser: prepared.authUser, AliasEnabled: prepared.aliasEnabled, InboundAlias: prepared.alias,
		DefaultOutboundTag: prepared.defaultTag,
	})
	if err != nil {
		return startupFailure(logger, "routing owner")
	}
	ctx, err := dispatcher.ContextWithNativeVPNRouting(context.Background(), owner, prepared.guards)
	if err != nil {
		_ = owner.Close()
		return startupFailure(logger, "routing guards")
	}
	xlog.RegisterHandler(privateLogHandler{logger: logger, level: prepared.level, enabled: prepared.diagnostics, phase: "configuration"})
	stage, err := activateNativeRoutingCandidate(owner, func() (routingRuntime, error) {
		instance, err := core.NewWithContext(ctx, prepared.config)
		if err != nil {
			return nil, err
		}
		return instance, nil
	}, func(candidate routingRuntime) error {
		return owner.Seal(candidate.(*core.Instance))
	}, func(candidate routingRuntime) error {
		return publishPrivateRuntime(candidate.(*core.Instance), owner)
	})
	if err != nil {
		return startupFailure(logger, "routing "+stage)
	}
	xlog.RegisterHandler(privateLogHandler{logger: logger, level: prepared.level, enabled: prepared.diagnostics, phase: "runtime"})
	return nil
}
