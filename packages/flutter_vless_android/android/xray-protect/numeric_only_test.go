package androidprotect

import (
	"context"
	"strings"
	"testing"
)

// No broker, FD, socket, resolver or Core is created by this control.
func TestNativeStrictResolverNeverDelegates(t *testing.T) {
	for _, network := range []string{"tcp", "udp", "unix"} {
		conn, err := refuseResolverDial(context.Background(), network, "private-canary.invalid:53")
		if conn != nil || err == nil || strings.Contains(err.Error(), "private-canary") {
			t.Fatal("strict physical resolver escaped closed refusal")
		}
	}
}
