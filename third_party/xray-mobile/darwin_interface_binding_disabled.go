//go:build !darwin || !flutter_vless_darwin_interface_binding

package XRay

// A stock or non-Darwin artifact must not claim mandatory interface binding.
func DarwinInterfaceBindingCapability() int64 { return 0 }
