// Package nativeconfig builds pure preparation requirements from this pinned
// Core's compiled types. A plan is not a claim of protected runtime support.
// It never starts Core, resolves a name, opens a socket, or rewrites caller DNS.
package nativeconfig

import (
	"fmt"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/freedom"
	proxyhttp "github.com/xtls/xray-core/proxy/http"
	proxyhysteria "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/loopback"
	proxymasque "github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	vless "github.com/xtls/xray-core/proxy/vless/outbound"
	vmess "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"github.com/xtls/xray-core/transport/internet/xdrive"
	"google.golang.org/protobuf/proto"
)

type Role string

const (
	RoleDrop     Role = "drop"
	RoleDispatch Role = "dispatch"
	RoleTarget   Role = "dynamic-target"
	RoleDNS      Role = "dns"
	RoleEndpoint Role = "endpoint"
)

type RequirementCode string

const (
	RequireCallerDNS       RequirementCode = "caller-dns"
	RequireDynamicTarget   RequirementCode = "dynamic-target"
	RequireRedispatch      RequirementCode = "redispatch"
	RequireDatagram        RequirementCode = "datagram-runtime"
	RequirePeerDNS         RequirementCode = "peer-inner-dns"
	RequireChain           RequirementCode = "dialer-chain"
	RequireServiceLookup   RequirementCode = "srv-txt-lookup"
	RequireFinalMask       RequirementCode = "finalmask-runtime"
	RequireSecurityLookup  RequirementCode = "security-auxiliary-lookup"
	RequireDownload        RequirementCode = "xhttp-download-runtime"
	RequireServiceEndpoint RequirementCode = "transport-service-endpoint"
	RequireEndpointName    RequirementCode = "endpoint-name-preparation"
)

// A requirement refers only to an owned source/endpoint index. Codes are safe
// diagnostics; hostnames, tags, protobuf errors and credentials are not errors.
type Requirement struct {
	Code          RequirementCode
	SourceIndex   int
	EndpointIndex int // -1 means the outbound as a whole
}

type ErrorCode string

const (
	InvalidSource        ErrorCode = "invalid-source"
	InvalidCompiled      ErrorCode = "invalid-compiled-config"
	InvalidEndpoint      ErrorCode = "invalid-endpoint"
	UnsupportedRole      ErrorCode = "unsupported-outbound-role"
	UnsupportedTransport ErrorCode = "unsupported-transport-role"
	InvalidDownload      ErrorCode = "invalid-download-settings"
)

type SourceError struct {
	SourceIndex int
	Code        ErrorCode
}

func (err *SourceError) Error() string {
	return fmt.Sprintf("native preparation source %d: %s", err.SourceIndex, err.Code)
}

type EndpointRole string

const (
	EndpointServer   EndpointRole = "server"
	EndpointPeer     EndpointRole = "peer"
	EndpointDownload EndpointRole = "download"
	EndpointOverride EndpointRole = "target-override"
	EndpointDNS      EndpointRole = "dns-rewrite"
)

// Logical is the target supplied to Core's transport; Physical is its known
// outer socket target. Dynamic means that Physical is not a complete fixed
// socket destination (e.g. freedom's port-only override or XDRIVE services).
// ChainTag is an internal routing reference, never a source identity.
type Endpoint struct {
	Role      EndpointRole
	Logical   net.Destination
	Physical  net.Destination
	Dynamic   bool
	Transport string
	ChainTag  string
	Socket    *internet.SocketConfig
}

type OutboundPlan struct {
	SourceIndex  int
	Source       *core.OutboundHandlerConfig
	Family       string // canonical typed family; direct/block aliases compile identically
	ProxyType    string
	Role         Role
	Endpoints    []Endpoint
	Requirements []Requirement
}

// AnalyzeOutbound inspects one actual compiled handler, not a JSON protocol
// whitelist. SourceIndex and Source retain native identity even for empty or
// duplicate tags. All parsed working data is detached from the caller's proto.
func AnalyzeOutbound(sourceIndex int, source *core.OutboundHandlerConfig) (plan OutboundPlan, err error) {
	defer func() {
		// ToMemoryStreamConfig uses common.Must for malformed typed mask settings.
		// Never export that panic's potentially private text.
		if recover() != nil {
			plan = OutboundPlan{}
			err = &SourceError{sourceIndex, InvalidCompiled}
		}
	}()
	bad := func(code ErrorCode) (OutboundPlan, error) { return OutboundPlan{}, &SourceError{sourceIndex, code} }
	if sourceIndex < 0 || source == nil || source.ProxySettings == nil {
		return bad(InvalidSource)
	}
	working := proto.Clone(source).(*core.OutboundHandlerConfig)
	proxy, parseErr := working.ProxySettings.GetInstance()
	if parseErr != nil {
		return bad(InvalidCompiled)
	}
	plan = OutboundPlan{SourceIndex: sourceIndex, Source: source, ProxyType: working.ProxySettings.Type}
	var sender *proxyman.SenderConfig
	if working.SenderSettings != nil {
		value, parseErr := working.SenderSettings.GetInstance()
		if parseErr != nil {
			return bad(InvalidCompiled)
		}
		var ok bool
		sender, ok = value.(*proxyman.SenderConfig)
		if !ok {
			return bad(InvalidCompiled)
		}
	}
	var server *protocol.ServerEndpoint
	switch settings := proxy.(type) {
	case *blackhole.Config:
		plan.Family, plan.Role = "blackhole", RoleDrop
	case *loopback.Config:
		plan.Family, plan.Role = "loopback", RoleDispatch
		plan.require(RequireRedispatch, -1)
	case *freedom.Config:
		plan.Family, plan.Role = "freedom", RoleTarget
		plan.require(RequireDynamicTarget, -1)
		plan.require(RequireCallerDNS, -1)
		if override := settings.GetDestinationOverride().GetServer(); override != nil {
			if override.Port > 65535 {
				return bad(InvalidEndpoint)
			}
			value := net.Destination{Port: net.Port(override.Port)}
			if override.Address != nil {
				address := override.Address.AsAddress()
				// Freedom treats unspecified IPs as no address override.
				if address != net.AnyIP && address != net.AnyIPv6 {
					value.Address = address
				}
			}
			plan.Endpoints = append(plan.Endpoints, Endpoint{Role: EndpointOverride, Logical: value, Physical: value, Dynamic: true})
		}
	case *proxydns.Config:
		plan.Family, plan.Role = "dns", RoleDNS
		plan.require(RequireCallerDNS, -1)
		if settings.RewriteServer != nil {
			if settings.RewriteServer.Port > 65535 {
				return bad(InvalidEndpoint)
			}
			value := settings.RewriteServer.AsDestination()
			plan.Endpoints = append(plan.Endpoints, Endpoint{Role: EndpointDNS, Logical: value, Physical: value, Dynamic: !fixedDestination(value)})
		}
	case *proxyhttp.ClientConfig:
		plan.Family, plan.Role, server = "http", RoleEndpoint, settings.Server
	case *shadowsocks.ClientConfig:
		plan.Family, plan.Role, server = "shadowsocks", RoleEndpoint, settings.Server
	case *shadowsocks_2022.ClientConfig:
		plan.Family, plan.Role = "shadowsocks", RoleEndpoint
		server = &protocol.ServerEndpoint{Address: settings.Address, Port: settings.Port}
	case *socks.ClientConfig:
		plan.Family, plan.Role, server = "socks", RoleEndpoint, settings.Server
	case *vless.Config:
		plan.Family, plan.Role, server = "vless", RoleEndpoint, settings.Vnext
	case *vmess.Config:
		plan.Family, plan.Role, server = "vmess", RoleEndpoint, settings.Receiver
	case *trojan.ClientConfig:
		plan.Family, plan.Role, server = "trojan", RoleEndpoint, settings.Server
	case *proxyhysteria.ClientConfig:
		plan.Family, plan.Role, server = "hysteria", RoleEndpoint, settings.Server
	case *proxymasque.ClientConfig:
		plan.Family, plan.Role, server = "masque", RoleEndpoint, settings.Server
		plan.require(RequirePeerDNS, -1)
	case *wireguard.DeviceConfig:
		plan.Family, plan.Role = "wireguard", RoleEndpoint
		if !settings.IsClient || len(settings.Peers) == 0 {
			return bad(InvalidEndpoint)
		}
		plan.require(RequirePeerDNS, -1)
		for _, peer := range settings.Peers {
			if peer == nil {
				return bad(InvalidEndpoint)
			}
			// Core itself uses ParseDestination for the peer endpoint, never DNS here.
			value, parseErr := net.ParseDestination("udp:" + peer.Endpoint)
			if parseErr != nil || !fixedDestination(value) {
				return bad(InvalidEndpoint)
			}
			plan.Endpoints = append(plan.Endpoints, Endpoint{Role: EndpointPeer, Logical: value, Physical: value, Transport: "udp"})
		}
	default:
		return bad(UnsupportedRole)
	}
	if plan.Role == RoleEndpoint && plan.Family != "wireguard" {
		if server == nil || server.Address == nil || server.Port == 0 || server.Port > 65535 {
			return bad(InvalidEndpoint)
		}
		value := net.TCPDestination(server.Address.AsAddress(), net.Port(server.Port))
		if !fixedDestination(value) {
			return bad(InvalidEndpoint)
		}
		plan.Endpoints = append(plan.Endpoints, Endpoint{Role: EndpointServer, Logical: value, Physical: value})
	}
	// Drop/redispatch do not dial the configured stream. Inspecting an ignored
	// stream as if it were a physical endpoint would create false requirements.
	if plan.Role == RoleDrop || plan.Role == RoleDispatch {
		return plan, nil
	}
	var stream *internet.StreamConfig
	if sender != nil {
		stream = sender.StreamSettings
	}
	memory, parseErr := internet.ToMemoryStreamConfig(stream)
	if parseErr != nil {
		return bad(InvalidCompiled)
	}
	for index := range plan.Endpoints {
		if plan.Family == "wireguard" {
			plan.Endpoints[index].Socket = cloneSocket(memory.SocketSettings)
			plan.streamRequirements(memory, index)
			plan.require(RequireDatagram, index)
			continue
		}
		if plan.Role != RoleEndpoint {
			plan.Endpoints[index].Socket = cloneSocket(memory.SocketSettings)
			plan.streamRequirements(memory, index)
			continue
		}
		if code := plan.applyStream(memory, index, 0); code != "" {
			return bad(code)
		}
	}
	if len(plan.Endpoints) == 0 {
		plan.streamRequirements(memory, -1)
	}
	for index, endpoint := range plan.Endpoints {
		if !endpoint.Dynamic && endpoint.Physical.Address != nil && endpoint.Physical.Address.Family().IsDomain() {
			plan.require(RequireEndpointName, index)
		}
	}
	return plan, nil
}

func fixedDestination(value net.Destination) bool {
	return value.Address != nil && value.Address.String() != "" && value.Port != 0 &&
		(value.Network == net.Network_TCP || value.Network == net.Network_UDP)
}

func cloneSocket(value *internet.SocketConfig) *internet.SocketConfig {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*internet.SocketConfig)
}

func (plan *OutboundPlan) require(code RequirementCode, endpoint int) {
	plan.Requirements = append(plan.Requirements, Requirement{code, plan.SourceIndex, endpoint})
}

func (plan *OutboundPlan) streamRequirements(memory *internet.MemoryStreamConfig, index int) {
	if memory.SocketSettings != nil {
		if memory.SocketSettings.DialerProxy != "" {
			plan.require(RequireChain, index)
		}
		if memory.SocketSettings.AddressPortStrategy != internet.AddressPortStrategy_None {
			plan.require(RequireServiceLookup, index)
		}
	}
	if memory.FinalMask != nil || memory.QuicParams != nil {
		plan.require(RequireFinalMask, index)
	}
	if security, ok := memory.SecuritySettings.(*tls.Config); ok &&
		(security.EchConfigList != "" || len(security.EchServerKeys) != 0 || security.EchSocketSettings != nil) {
		plan.require(RequireSecurityLookup, index)
	}
}

func (plan *OutboundPlan) applyStream(memory *internet.MemoryStreamConfig, index, depth int) ErrorCode {
	endpoint := &plan.Endpoints[index]
	endpoint.Transport = memory.ProtocolName
	endpoint.Socket = cloneSocket(memory.SocketSettings)
	if memory.SocketSettings != nil {
		endpoint.ChainTag = memory.SocketSettings.DialerProxy
	}
	plan.streamRequirements(memory, index)
	network := net.Network_TCP
	switch settings := memory.ProtocolSettings.(type) {
	case *tcp.Config, *grpc.Config, *websocket.Config, *httpupgrade.Config:
	case *kcp.Config, *hysteria.Config:
		network = net.Network_UDP
	case *masque.Config:
		security, ok := memory.SecuritySettings.(*tls.Config)
		if !ok {
			return UnsupportedTransport
		}
		// The actual MASQUE transport chooses H2 only when h2 is present and h3 absent.
		h2, h3 := false, false
		for _, alpn := range security.NextProtocol {
			h2 = h2 || alpn == "h2"
			h3 = h3 || alpn == "h3"
		}
		if !h2 || h3 {
			network = net.Network_UDP
		}
	case *splithttp.Config:
		if security, ok := memory.SecuritySettings.(*tls.Config); ok && len(security.NextProtocol) == 1 && security.NextProtocol[0] == "h3" {
			network = net.Network_UDP
		}
		if settings.DownloadSettings != nil && depth == 0 {
			// Dial lazily converts this compiled object, then applies penetrate.
			download := memory.DownloadSettings
			if download == nil {
				var err error
				download, err = internet.ToMemoryStreamConfig(settings.DownloadSettings)
				if err != nil {
					return InvalidDownload
				}
				if memory.SocketSettings != nil && memory.SocketSettings.Penetrate {
					download.SocketSettings = memory.SocketSettings
				}
			}
			if download.Destination == nil || !fixedDestination(*download.Destination) {
				return InvalidDownload
			}
			if _, ok := download.ProtocolSettings.(*splithttp.Config); !ok {
				return InvalidDownload
			}
			value := *download.Destination
			plan.Endpoints = append(plan.Endpoints, Endpoint{Role: EndpointDownload, Logical: value, Physical: value})
			next := len(plan.Endpoints) - 1
			plan.require(RequireDownload, next)
			if code := plan.applyStream(download, next, depth+1); code != "" {
				return code
			}
		}
		// Core's download path calls getHTTPClient, not Dial: a second nested
		// downloadSettings is not used to create another physical connection.
	case *xdrive.Config:
		// XDRIVE obtains service URLs at runtime. Its logical proxy endpoint is
		// not that service's physical destination; only fronting is fixed here.
		endpoint.Dynamic = true
		endpoint.Physical = net.Destination{}
		if memory.Destination != nil {
			endpoint.Physical = *memory.Destination
		}
		plan.require(RequireServiceEndpoint, index)
	default:
		return UnsupportedTransport
	}
	// append above may have reallocated the endpoint slice.
	endpoint = &plan.Endpoints[index]
	if !endpoint.Dynamic {
		endpoint.Physical.Network = network
	}
	if network == net.Network_UDP {
		plan.require(RequireDatagram, index)
	}
	if plan.Family == "hysteria" {
		if _, ok := memory.ProtocolSettings.(*hysteria.Config); !ok {
			return UnsupportedTransport
		}
	}
	if plan.Family == "masque" {
		if _, ok := memory.ProtocolSettings.(*masque.Config); !ok {
			return UnsupportedTransport
		}
	}
	return ""
}
