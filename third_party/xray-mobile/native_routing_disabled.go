//go:build !flutter_vless_vpn_routing

package XRay

// The presence of additive symbols is not a capability. Ordinary artifacts
// explicitly refuse the optional path before parsing a candidate or using Core.
func RoutingCapability() int64 { return 0 }

func CheckRoutingPrivate(config, spec []byte) int64 { return 32 }

func StartRoutingPrivate(config, spec []byte, logger Logger) error {
	return startupFailure(logger, "unsupported native routing")
}
