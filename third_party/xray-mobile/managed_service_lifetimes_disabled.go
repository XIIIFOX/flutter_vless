//go:build !flutter_vless_managed_service_lifetimes

package XRay

func GeodataLifetimeCapability() int64 { return 0 }
func XdriveLifetimeCapability() int64  { return 0 }
