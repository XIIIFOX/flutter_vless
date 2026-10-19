package core

import (
	"context"

	"github.com/xtls/xray-core/features/routing"
)

// Invoked only on NewWithContext's init failure. Ordinary constructors retain
// their existing behavior. Revoke the opt-in routing capability before closing
// admitted partial features; cleanup errors must not replace the init error.
func nativeRoutingConstructionFailed(ctx context.Context, server *Instance) {
	owner, present := routing.NativeRoutingOwnerFromContext(ctx)
	if !present {
		return
	}
	if owner != nil {
		_ = owner.Close()
	}
	// A present typed-nil seed is malformed, but still owns its partial Core.
	if server != nil {
		_ = server.Close()
	}
}
