//go:build !flutter_vless_vpn_routing

package XRay

import "testing"

func TestNativeRoutingDefaultArtifactRefuses(t *testing.T) {
	if RoutingCapability() != 0 {
		t.Fatal("ordinary Core advertised an absent optional hook")
	}
	if code := CheckRoutingPrivate([]byte("invalid candidate"), nil); code != 32 {
		t.Fatal("ordinary artifact parsed or accepted optional configuration", code)
	}
	if err := StartRoutingPrivate([]byte("invalid candidate"), nil, nil); err == nil {
		t.Fatal("ordinary artifact started optional routing")
	}
}
