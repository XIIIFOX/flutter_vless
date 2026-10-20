//go:build darwin && flutter_vless_darwin_interface_binding

package XRay

import "github.com/xtls/xray-core/transport/internet"

// This build cannot compile against a Core without the guarded binding patch.
func DarwinInterfaceBindingCapability() int64 {
	return int64(internet.DarwinInterfaceBindingCapability)
}
