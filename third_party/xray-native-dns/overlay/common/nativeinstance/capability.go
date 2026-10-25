// Package nativeinstance is an unpublished, opt-in development entry. It does
// not change host DNS/routes or qualify any mobile/desktop packet path. The
// admitted subset is deliberately smaller than ordinary Xray configuration.
package nativeinstance

import (
	"errors"
	"net/netip"
	"time"
)

const CapabilityID = "native-instance-preview-1"
const CoreCommit = "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74"
const maxDocumentBytes = 4 << 20
const maxLookupTimeout = 4 * time.Second
const closeWait = 3 * time.Second

// Published remains false until native host protection and platform qualification.
type Capability struct {
	Schema         int
	ID, CoreCommit string
	Published      bool
}

func Capabilities() Capability { return Capability{1, CapabilityID, CoreCommit, false} }

// Policy is trusted side metadata; no configuration field can grant it. Resolver
// is a literal IPv4 TCP destination and DefaultOutboundIndex is source identity,
// including an untagged handler. The source tags are never rewritten.
type Policy struct {
	RequiredCapability   string
	Resolver             netip.AddrPort
	DefaultOutboundIndex int
	LookupTimeout        time.Duration
	SystemDNSBridge      *SystemDNSBridgePolicy
	ManagedInput         *ManagedInputPolicy
}

// Errors are a closed vocabulary; source credentials/decoder/Core errors are
// deliberately absent. Callers must still avoid logging source data themselves.
var (
	ErrDocument    = errors.New("native preview document rejected")
	ErrPolicy      = errors.New("native preview policy rejected")
	ErrUnsupported = errors.New("native preview configuration unavailable")
	ErrStart       = errors.New("native preview start failed")
	ErrClosed      = errors.New("native preview runtime closed")
	ErrBusy        = errors.New("native preview lookup busy")
	ErrLookup      = errors.New("native preview lookup failed")
	ErrDrain       = errors.New("native preview cleanup incomplete")
	ErrDNSQuery    = errors.New("native preview DNS query rejected")
)

func checkedPolicy(policy Policy) (Policy, error) {
	if policy.RequiredCapability != CapabilityID || !policy.Resolver.IsValid() ||
		!policy.Resolver.Addr().Is4() || policy.Resolver.Addr().Zone() != "" ||
		policy.Resolver.Addr().IsUnspecified() || policy.Resolver.Addr().IsMulticast() ||
		policy.Resolver.Port() == 0 || policy.DefaultOutboundIndex < 0 {
		return Policy{}, ErrPolicy
	}
	if policy.LookupTimeout == 0 {
		policy.LookupTimeout = maxLookupTimeout
	}
	if policy.LookupTimeout < time.Millisecond || policy.LookupTimeout > maxLookupTimeout {
		return Policy{}, ErrPolicy
	}
	if policy.SystemDNSBridge != nil {
		bridge := *policy.SystemDNSBridge // Freeze caller-owned pointer metadata.
		if !bridge.VirtualIPv4.IsValid() || !bridge.VirtualIPv4.Is4() || bridge.VirtualIPv4.Zone() != "" ||
			bridge.VirtualIPv4.IsUnspecified() || bridge.VirtualIPv4.IsMulticast() || bridge.VirtualIPv4.IsLoopback() ||
			bridge.VirtualIPv4 == policy.Resolver.Addr() {
			return Policy{}, ErrPolicy
		}
		policy.SystemDNSBridge = &bridge
	}
	if policy.ManagedInput != nil {
		input := *policy.ManagedInput
		if policy.SystemDNSBridge == nil || !input.Listen.IsValid() || input.Listen.Addr() != netip.MustParseAddr("127.0.0.1") || input.Listen.Port() == 0 ||
			len(input.Username) < 1 || len(input.Username) > 255 || len(input.Password) < 1 || len(input.Password) > 255 {
			return Policy{}, ErrPolicy
		}
		policy.ManagedInput = &input
	}
	return policy, nil
}
