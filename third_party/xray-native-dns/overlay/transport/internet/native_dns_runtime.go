package internet

// Construction identities stay separate from immutable endpoint preparation.
// This registry is never populated from a request or from tag-only lookups.
import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/features/outbound"
)

type nativeDNSRuntimeEntry struct {
	handler outbound.Handler
	scope   *NativeDNSHandler
}

type nativeDNSRuntime struct {
	entries map[any]nativeDNSRuntimeEntry
	manager outbound.Manager
	sealed  bool
}

// The concrete manager validates membership and seals mutation under its own
// Add/Remove mutex. ListHandlers followed by Dispatch cannot provide this gate.
type nativeDNSSealableManager interface {
	SealNativeDNSHandlers([]outbound.Handler) error
}

// RegisterRuntime is called exactly once after the actual handler is complete,
// before NewHandler returns it to the manager. It does not authorize DNS egress.
func (scope *NativeDNSHandler) RegisterRuntime(handler outbound.Handler) error {
	if scope == nil || scope.owner == nil {
		return ErrNativeDNSScope
	}
	owner := scope.owner
	owner.instanceLock.Lock()
	defer owner.instanceLock.Unlock()
	if owner.closed.Load() {
		return ErrNativeDNSClosed
	}
	if owner.runtime.sealed || !nativeDNSPointer(handler) || !nativeDNSPointer(scope.manager) || handler.Tag() != scope.binding.tag {
		return ErrNativeDNSIdentity
	}
	if _, exists := owner.runtime.entries[scope.key]; exists {
		return ErrNativeDNSIdentity
	}
	if owner.runtime.manager != nil && owner.runtime.manager != scope.manager {
		return ErrNativeDNSIdentity
	}
	for _, entry := range owner.runtime.entries {
		if entry.handler == handler {
			return ErrNativeDNSIdentity
		}
	}
	if owner.runtime.entries == nil {
		owner.runtime.entries = make(map[any]nativeDNSRuntimeEntry)
	}
	owner.runtime.manager = scope.manager
	owner.runtime.entries[scope.key] = nativeDNSRuntimeEntry{handler, scope}
	return nil
}

func nativeDNSPointer(value any) bool {
	identity := reflect.ValueOf(value)
	return identity.IsValid() && identity.Kind() == reflect.Pointer && !identity.IsNil()
}

// SealNativeDNSRuntime runs only after the same Core.NewWithContext succeeds,
// before Start. It supports untagged handlers without renaming/reordering them.
// Hot Add/Remove becomes explicitly unavailable for this sealed instance.
func (owner *NativeDNSOwner) SealNativeDNSRuntime(instance any, manager outbound.Manager) error {
	if owner == nil {
		return ErrNativeDNSScope
	}
	owner.instanceLock.Lock()
	defer owner.instanceLock.Unlock()
	if owner.closed.Load() {
		return ErrNativeDNSClosed
	}
	if !nativeDNSPointer(instance) || !nativeDNSPointer(manager) || owner.instanceKey != instance ||
		owner.runtime.sealed || owner.runtime.manager != manager || len(owner.runtime.entries) != len(owner.bindings) {
		return ErrNativeDNSIdentity
	}
	sealable, ok := manager.(nativeDNSSealableManager)
	if !ok {
		return ErrNativeDNSUnsupported
	}
	expected := make([]outbound.Handler, 0, len(owner.bindings))
	for key := range owner.bindings {
		entry, exists := owner.runtime.entries[key]
		if !exists || entry.scope.owner != owner || entry.scope.manager != manager {
			return ErrNativeDNSIdentity
		}
		expected = append(expected, entry.handler)
	}
	if err := sealable.SealNativeDNSHandlers(expected); err != nil {
		return err
	}
	if owner.closed.Load() {
		return ErrNativeDNSClosed
	}
	owner.runtime.sealed = true
	return nil
}

// NativeDNSRuntimeHandler returns only a sealed, exact source-index identity.
// The caller must additionally authorize the chosen handler's role/settings.
func (owner *NativeDNSOwner) NativeDNSRuntimeHandler(instance any, sourceIndex int) (outbound.Handler, *NativeDNSHandler, error) {
	if owner == nil {
		return nil, nil, ErrNativeDNSScope
	}
	owner.instanceLock.Lock()
	defer owner.instanceLock.Unlock()
	if owner.closed.Load() {
		return nil, nil, ErrNativeDNSClosed
	}
	if !nativeDNSPointer(instance) || owner.instanceKey != instance || !owner.runtime.sealed {
		return nil, nil, ErrNativeDNSIdentity
	}
	for _, entry := range owner.runtime.entries {
		if entry.scope.binding.sourceIndex == sourceIndex {
			return entry.handler, entry.scope, nil
		}
	}
	return nil, nil, ErrNativeDNSIdentity
}

// NativeDNSRuntimeOperation validates both the captured Core and source identity
// and binds cancellation to the owner. No first request's metadata is retained.
func (owner *NativeDNSOwner) NativeDNSRuntimeOperation(ctx context.Context, instance any, sourceIndex int) (context.Context, func(), outbound.Handler, error) {
	handler, scope, err := owner.NativeDNSRuntimeHandler(instance, sourceIndex)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, err = scope.Context(ctx, false)
	if err != nil {
		return nil, nil, nil, err
	}
	operation, release, err := NativeDNSOperationContext(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return operation, release, handler, nil
}
