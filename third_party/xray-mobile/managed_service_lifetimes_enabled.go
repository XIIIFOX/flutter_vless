//go:build flutter_vless_managed_service_lifetimes

package XRay

import (
	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

// These symbols exist only after both exact-source ownership patches apply.
func GeodataLifetimeCapability() int64 { return geodata.NativeLifetimeCapability() }
func XdriveLifetimeCapability() int64  { return xdrive.NativeLifetimeCapability() }
