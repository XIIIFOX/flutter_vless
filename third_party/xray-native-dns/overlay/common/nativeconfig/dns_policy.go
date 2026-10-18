package nativeconfig

// Root DNS has its own socket/resolver purposes. Outbound transport pins do
// not authorize a DNS server to use the system resolver or a local QUIC dial.
// This analysis never constructs a DNS server, resolves a name, or rewrites the
// caller's compiled document. It is unpublished native preparation metadata.
import (
	"fmt"
	"net/url"
	"strings"

	appdns "github.com/xtls/xray-core/app/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"golang.org/x/net/idna"
)

type RootDNSCapability string

const (
	DNSRemoteUDP      RootDNSCapability = "remote-udp"
	DNSRemoteTCP      RootDNSCapability = "remote-tcp"
	DNSRemoteDoH      RootDNSCapability = "remote-doh"
	DNSRemoteH2C      RootDNSCapability = "remote-h2c"
	DNSLocalSystem    RootDNSCapability = "local-system"
	DNSLocalTCP       RootDNSCapability = "local-tcp"
	DNSLocalDoH       RootDNSCapability = "local-doh"
	DNSLocalH2C       RootDNSCapability = "local-h2c"
	DNSLocalQUIC      RootDNSCapability = "local-quic"
	DNSFake           RootDNSCapability = "fake-dns"
	DNSSystemFamilies RootDNSCapability = "system-families"
	DNSScript         RootDNSCapability = "script"
	DNSResolverName   RootDNSCapability = "resolver-name"
)

// AppIndex/ServerIndex refer to the compiled document, never tags. -1 means
// the essential implicit DNS feature / a root-wide requirement respectively.
// Destination is separate from outbound Endpoint: it cannot be used as a
// transport pin. Tags and URLs in source are not changed by this plan.
type RootDNSRequirement struct {
	AppIndex, ServerIndex int
	Capability            RootDNSCapability
	Destination           xnet.Destination
	// Tag is configured source metadata with server-over-root precedence,
	// not a guaranteed effective runtime tag. Core may generate a root tag;
	// its implicit local client uses an empty tag even with root.Tag set.
	Tag string
}

type RootDNSPlan struct {
	Requirements []RootDNSRequirement
}

// Diagnostic fields are closed metadata; no source URLs, credentials, tags,
// script paths, names, protobuf decoder text or server replies are formatted.
type RootDNSError struct {
	AppIndex, ServerIndex int
	Code                  string
	Capability            RootDNSCapability
}

func (failure *RootDNSError) Error() string {
	return fmt.Sprintf("native DNS app[%d] server[%d]: %s (%s)", failure.AppIndex, failure.ServerIndex, failure.Code, failure.Capability)
}

// AnalyzeRootDNS mirrors the pinned app/dns.NewServer dispatch order, including
// its implicit localhost fallback for missing/empty servers. A remote URL is
// routed by Core; +local and DoQ are different paths and require separate host
// capabilities. Classification is not runtime qualification of any capability.
func AnalyzeRootDNS(configuration *core.Config) (RootDNSPlan, error) {
	plan := RootDNSPlan{}
	if configuration == nil {
		return plan, &RootDNSError{-1, -1, "invalid-config", ""}
	}
	seen := false
	for appIndex, message := range configuration.App {
		if message == nil || message.Type != "xray.app.dns.Config" {
			continue
		}
		if seen {
			return RootDNSPlan{}, &RootDNSError{appIndex, -1, "duplicate-dns-feature", ""}
		}
		seen = true
		instance, err := message.GetInstance()
		if err != nil {
			return RootDNSPlan{}, &RootDNSError{appIndex, -1, "invalid-dns-feature", ""}
		}
		configuration, ok := instance.(*appdns.Config)
		if !ok || configuration == nil {
			return RootDNSPlan{}, &RootDNSError{appIndex, -1, "invalid-dns-feature", ""}
		}
		if err := dnsQueryStrategy(configuration.QueryStrategy); err != nil {
			return RootDNSPlan{}, &RootDNSError{appIndex, -1, "invalid-query-strategy", ""}
		}
		add := func(serverIndex int, capability RootDNSCapability, destination xnet.Destination, tag string) {
			plan.Requirements = append(plan.Requirements, RootDNSRequirement{appIndex, serverIndex, capability, destination, tag})
		}
		if configuration.QueryStrategy == appdns.QueryStrategy_USE_SYS {
			add(-1, DNSSystemFamilies, xnet.Destination{}, configuration.Tag)
		}
		if configuration.Script != "" {
			add(-1, DNSScript, xnet.Destination{}, configuration.Tag)
		}
		if len(configuration.NameServer) == 0 {
			add(-1, DNSLocalSystem, xnet.Destination{}, configuration.Tag)
		}
		for serverIndex, server := range configuration.NameServer {
			if server == nil || server.Address == nil {
				return RootDNSPlan{}, &RootDNSError{appIndex, serverIndex, "invalid-server", ""}
			}
			if err := dnsQueryStrategy(server.QueryStrategy); err != nil {
				return RootDNSPlan{}, &RootDNSError{appIndex, serverIndex, "invalid-query-strategy", ""}
			}
			if (configuration.QueryStrategy == appdns.QueryStrategy_USE_IP4 && server.QueryStrategy == appdns.QueryStrategy_USE_IP6) ||
				(configuration.QueryStrategy == appdns.QueryStrategy_USE_IP6 && server.QueryStrategy == appdns.QueryStrategy_USE_IP4) {
				return RootDNSPlan{}, &RootDNSError{appIndex, serverIndex, "empty-query-families", ""}
			}
			tag := server.Tag
			if tag == "" {
				tag = configuration.Tag
			}
			if server.QueryStrategy == appdns.QueryStrategy_USE_SYS {
				add(serverIndex, DNSSystemFamilies, xnet.Destination{}, tag)
			}
			capability, destination, err := classifyDNSServer(server.Address)
			if err != nil {
				return RootDNSPlan{}, &RootDNSError{appIndex, serverIndex, "invalid-server", ""}
			}
			add(serverIndex, capability, destination, tag)
			if destination.Address != nil && destination.Address.Family().IsDomain() {
				add(serverIndex, DNSResolverName, destination, tag)
			}
		}
	}
	if !seen {
		plan.Requirements = append(plan.Requirements, RootDNSRequirement{AppIndex: -1, ServerIndex: -1, Capability: DNSLocalSystem})
	}
	return plan, nil
}

func dnsQueryStrategy(strategy appdns.QueryStrategy) error {
	switch strategy {
	case appdns.QueryStrategy_USE_IP, appdns.QueryStrategy_USE_IP4, appdns.QueryStrategy_USE_IP6, appdns.QueryStrategy_USE_SYS:
		return nil
	default:
		return &RootDNSError{-1, -1, "invalid-query-strategy", ""}
	}
}

// ValidateRootDNSCapabilities is fail-closed. A native host supplies only its
// actually qualified capabilities; no caller JSON key can grant one. Even an
// all-true set is not proof of DNS graph termination, socket protection, assets,
// family support, script sandboxing, or preflight; those remain separate gates.
func ValidateRootDNSCapabilities(plan RootDNSPlan, supported map[RootDNSCapability]bool) error {
	for _, requirement := range plan.Requirements {
		if !supported[requirement.Capability] {
			return &RootDNSError{requirement.AppIndex, requirement.ServerIndex, "capability-unavailable", requirement.Capability}
		}
	}
	return nil
}

func classifyDNSServer(endpoint *xnet.Endpoint) (RootDNSCapability, xnet.Destination, error) {
	invalid := func() (RootDNSCapability, xnet.Destination, error) {
		return "", xnet.Destination{}, &RootDNSError{-1, -1, "invalid-server", ""}
	}
	if endpoint.Address == nil || endpoint.Port > 65535 {
		return invalid()
	}
	var address xnet.Address
	switch value := endpoint.Address.Address.(type) {
	case *xnet.IPOrDomain_Ip:
		if value == nil || len(value.Ip) != 4 && len(value.Ip) != 16 {
			return invalid()
		}
		address = xnet.IPAddress(append([]byte(nil), value.Ip...))
	case *xnet.IPOrDomain_Domain:
		if value == nil || value.Domain == "" {
			return invalid()
		}
		address = xnet.DomainAddress(value.Domain)
	default:
		return invalid()
	}
	if address.Family().IsDomain() {
		parsed, err := url.Parse(address.Domain())
		if err != nil {
			return invalid()
		}
		if strings.EqualFold(parsed.String(), "localhost") {
			return DNSLocalSystem, xnet.Destination{}, nil
		}
		if strings.EqualFold(parsed.String(), "fakedns") {
			return DNSFake, xnet.Destination{}, nil
		}
		var capability RootDNSCapability
		var port xnet.Port
		network := xnet.Network_TCP
		switch strings.ToLower(parsed.Scheme) {
		case "tcp":
			capability, port = DNSRemoteTCP, 53
		case "tcp+local":
			capability, port = DNSLocalTCP, 53
		case "https":
			capability, port = DNSRemoteDoH, 443
		case "h2c":
			capability, port = DNSRemoteH2C, 443 // Core changes this URL scheme to https too.
		case "https+local":
			capability, port = DNSLocalDoH, 443
		case "h2c+local":
			capability, port = DNSLocalH2C, 443
		case "quic+local":
			capability, port, network = DNSLocalQUIC, 853, xnet.Network_UDP
		}
		if capability != "" {
			if parsed.Hostname() == "" {
				return invalid()
			}
			if parsed.Port() != "" {
				var err error
				port, err = xnet.PortFromString(parsed.Port())
				if err != nil {
					return invalid()
				}
			}
			host := parsed.Hostname()
			switch capability {
			case DNSRemoteDoH, DNSRemoteH2C, DNSLocalDoH, DNSLocalH2C:
				// Go 1.27's net/http canonicalAddr applies IDNA before the
				// HTTP2 DialTLSContext hook. Core's TCP/QUIC constructors do
				// not, so this conversion belongs only to HTTP resolver roles.
				host = httpDNSResolverHost(host)
			}
			return capability, xnet.Destination{Network: network, Address: xnet.ParseAddress(host), Port: port}, nil
		}
	}
	// Like NewServer, an unrecognized scheme is not silently treated as DoH/TLS.
	// Core's UDP fallback would use that entire domain string, requiring its own
	// protected name plan; this classifier does not invent URL semantics for it.
	if endpoint.Network != xnet.Network_Unknown && endpoint.Network != xnet.Network_UDP {
		return invalid()
	}
	port := xnet.Port(endpoint.Port)
	if port == 0 {
		port = 53
	}
	return DNSRemoteUDP, xnet.UDPDestination(address, port), nil
}

func httpDNSResolverHost(host string) string {
	// Match net/http's ASCII fast path and its original-host fallback on an
	// IDNA error. This is metadata for the eventual dial, not a source rewrite.
	for index := 0; index < len(host); index++ {
		if host[index] >= 0x80 {
			if ascii, err := idna.Lookup.ToASCII(host); err == nil {
				return ascii
			}
			return host
		}
	}
	return host
}
