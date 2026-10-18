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
const CoreCommit = "92ccc939aaf4f8965f369cf0b142e005aeaa11d5"
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
	return policy, nil
}
