package nativecli

import XRay "github.com/EbrahimTahernejad/xray-mobile"

// MobileBackend delegates to the same factory used by the native bridge.
// A default build advertises capability zero and cannot activate this path.
// Importing the mobile package installs its private preflight log handler;
// an executable adding this command must preserve stock-command logging.
type MobileBackend struct{}

func (MobileBackend) Capability() int64               { return XRay.RoutingCapability() }
func (MobileBackend) Check(config, spec []byte) int64 { return XRay.CheckRoutingPrivate(config, spec) }
func (MobileBackend) Start(config, spec []byte) error {
	return XRay.StartRoutingPrivate(config, spec, nil)
}
func (MobileBackend) Stop() { XRay.Stop() }

var _ Backend = MobileBackend{}
