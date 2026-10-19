//go:build flutter_vless_vpn_routing

package XRay

import "testing"

func TestNativeRoutingOptionalArtifactCapability(t *testing.T) {
	if RoutingCapability() != 1 {
		t.Fatal("optional artifact omitted its capability")
	}
	if code := CheckRoutingPrivate(nil, nil); code != 16 {
		t.Fatal("invalid metadata did not fail before Core preparation", code)
	}
}
