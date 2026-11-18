//go:build flutter_vless_balancer_diagnostics

package nativecli

import XRay "github.com/EbrahimTahernejad/xray-mobile"

type MobileBalancerBackend struct{ Logger XRay.Logger }

func (MobileBalancerBackend) Capability() int64 { return XRay.BalancerDiagnosticsCapability() }
func (MobileBalancerBackend) CheckRouting(config, spec []byte) int64 {
	return XRay.CheckRoutingPrivate(config, spec)
}
func (backend MobileBalancerBackend) Start(config, spec []byte, inbound string, capacity int64) error {
	return XRay.StartCLIBalancerDiagnosticsPrivate(config, spec, inbound, capacity, backend.Logger)
}
func (MobileBalancerBackend) Snapshot() string { return XRay.ReadBalancerDiagnostics() }
func (MobileBalancerBackend) Disable()         { XRay.DisableBalancerDiagnostics() }
func (MobileBalancerBackend) Stop()            { XRay.Stop() }
