package nativeinstance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	appoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/nativeconfig"
	xnet "github.com/xtls/xray-core/common/net"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

// Prepared retains only a private immutable blueprint. Every Start clones it
// and binds the clone's actual pointers; neither tags nor JSON are regenerated.
type Prepared struct {
	source     []byte
	normalized []byte
	digest     string
	policy     Policy
	blueprint  *core.Config
}

func (p *Prepared) SourceDigest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

// PrepareJSON is structural only: Decode/Build and typed graph checks, with no
// Core construction, socket, resolver, environment change or asset download.
// Existing local geodata assets may be read by Core's pure configuration build.
func PrepareJSON(source []byte, requested Policy) (*Prepared, error) {
	silenceLogs() // Must precede decoder/build warnings. Isolated-process contract.
	policy, err := checkedPolicy(requested)
	if err != nil {
		return nil, err
	}
	if len(source) == 0 || len(source) > maxDocumentBytes {
		return nil, ErrDocument
	}
	retained := append([]byte(nil), source...)
	private, err := privateDocument(retained)
	if err != nil {
		return nil, ErrDocument
	}
	decoded, err := serial.DecodeJSONConfigStrict(bytes.NewReader(private))
	if err != nil {
		return nil, ErrDocument
	}
	if !admitDecoded(decoded) {
		return nil, ErrUnsupported
	}
	compiled, err := decoded.Build()
	if err != nil {
		return nil, ErrDocument
	}
	if err := admitCompiled(compiled, policy); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(retained)
	return &Prepared{retained, append([]byte(nil), private...), hex.EncodeToString(hash[:]), policy, compiled}, nil
}

// These gates run BEFORE Build, which otherwise applies Env and can construct
// unqualified stream/security/app configurations. Compiled gates remain final.
func admitDecoded(c *conf.Config) bool {
	if c == nil || len(c.Env) != 0 || c.Transport != nil || c.API != nil || c.Metrics != nil || c.Stats != nil ||
		c.Reverse != nil || c.FakeDNS != nil || c.Observatory != nil || c.BurstObservatory != nil || c.Version != nil || c.Geodata != nil {
		return false
	}
	if c.RouterConfig != nil && (len(c.RouterConfig.Balancers) != 0 || c.RouterConfig.Script != "") {
		return false
	}
	for _, item := range c.InboundConfigs {
		if strings.ToLower(item.Protocol) != "socks" || !plainDecodedStream(item.StreamSetting) {
			return false
		}
	}
	for _, item := range c.OutboundConfigs {
		protocol := strings.ToLower(item.Protocol)
		if protocol != "freedom" && protocol != "blackhole" || !plainDecodedStream(item.StreamSetting) ||
			item.SendThrough != nil || item.ProxySettings != nil || item.MuxSettings != nil ||
			item.TargetStrategy != "" && !strings.EqualFold(item.TargetStrategy, "AsIs") {
			return false
		}
	}
	return true
}

func plainDecodedStream(s *conf.StreamConfig) bool {
	if s == nil {
		return true
	}
	// Explicit plain TCP/raw selection is harmless. All optional transport
	// settings remain pending rather than relying on builders to ignore them.
	if s.Address != nil || s.Port != 0 || s.FinalMask != nil || s.TLSSettings != nil || s.REALITYSettings != nil ||
		s.RAWSettings != nil || s.TCPSettings != nil || s.XHTTPSettings != nil || s.SplitHTTPSettings != nil || s.KCPSettings != nil ||
		s.GRPCSettings != nil || s.WSSettings != nil || s.HTTPUPGRADESettings != nil || s.HysteriaSettings != nil ||
		s.MASQUESettings != nil || s.XDRIVESettings != nil || s.SocketSettings != nil {
		return false
	}
	if s.Security != "" && !strings.EqualFold(s.Security, "none") {
		return false
	}
	for _, method := range []*conf.TransportProtocol{s.Method, s.Network} {
		if method != nil && !strings.EqualFold(string(*method), "tcp") && !strings.EqualFold(string(*method), "raw") {
			return false
		}
	}
	return true
}

func admitCompiled(c *core.Config, p Policy) error {
	if c == nil || len(c.Extension) != 0 || len(c.Outbound) == 0 || len(c.Outbound) > 16 || len(c.Inbound) > 8 || p.DefaultOutboundIndex >= len(c.Outbound) {
		return ErrUnsupported
	}
	seen := map[string]bool{}
	for _, message := range c.App {
		if message == nil || seen[message.Type] {
			return ErrUnsupported
		}
		seen[message.Type] = true
		instance, err := message.GetInstance()
		if err != nil {
			return ErrUnsupported
		}
		switch value := instance.(type) {
		case *applog.Config:
			if value.ErrorLogType != applog.LogType_None || value.AccessLogType != applog.LogType_None || value.ErrorLogPath != "" || value.AccessLogPath != "" || value.EnableDnsLog {
				return ErrUnsupported
			}
		case *dispatcher.Config, *proxyman.InboundConfig, *proxyman.OutboundConfig, *policy.Config:
		case *appdns.Config:
			if !admitDNS(value) {
				return ErrUnsupported
			}
		case *router.Config:
			if value.Script != "" || len(value.BalancingRule) != 0 {
				return ErrUnsupported
			}
			for _, rule := range value.Rule {
				if rule == nil || rule.Webhook != nil {
					return ErrUnsupported
				}
				if _, ok := rule.TargetTag.(*router.RoutingRule_Tag); !ok {
					return ErrUnsupported
				}
			}
		default:
			return ErrUnsupported
		}
	}
	plan, err := nativeconfig.AnalyzeRootDNS(c)
	if err != nil {
		return ErrUnsupported
	}
	for _, requirement := range plan.Requirements {
		switch requirement.Capability {
		case nativeconfig.DNSLocalSystem:
		case nativeconfig.DNSRemoteTCP:
			if requirement.Destination.Address == nil || !requirement.Destination.Address.Family().IsIPv4() || requirement.Destination.Port == 0 {
				return ErrUnsupported
			}
		default:
			return ErrUnsupported
		}
	}
	tags := map[string]bool{}
	for index, item := range c.Outbound {
		if item == nil || item.ProxySettings == nil || item.SenderSettings == nil {
			return ErrUnsupported
		}
		if item.Tag != "" {
			if tags[item.Tag] {
				return ErrUnsupported
			}
			tags[item.Tag] = true
		}
		senderMessage, err := item.SenderSettings.GetInstance()
		if err != nil {
			return ErrUnsupported
		}
		sender, ok := senderMessage.(*proxyman.SenderConfig)
		if !ok || sender.TargetStrategy != internet.DomainStrategy_AS_IS {
			return ErrUnsupported
		}
		stream, err := internet.ToMemoryStreamConfig(sender.StreamSettings)
		if err != nil {
			return ErrUnsupported
		}
		proxy, err := item.ProxySettings.GetInstance()
		if err != nil {
			return ErrUnsupported
		}
		switch value := proxy.(type) {
		case *freedom.Config:
			if !simpleFreedom(value, sender, stream, index == p.DefaultOutboundIndex) {
				return ErrUnsupported
			}
			// AsIs is admitted only for the explicitly selected numeric policy egress;
			// named caller targets use Core root DNS through explicit UseIPv4.
			if index == p.DefaultOutboundIndex {
				if value.DomainStrategy != internet.DomainStrategy_AS_IS {
					return ErrUnsupported
				}
			} else if value.DomainStrategy != internet.DomainStrategy_USE_IP4 {
				return ErrUnsupported
			}
		case *blackhole.Config:
			if index == p.DefaultOutboundIndex || !appoutbound.NativeDNSPolicyAllowsEgress(&freedom.Config{}, sender, stream) {
				return ErrUnsupported
			}
		default:
			return ErrUnsupported
		}
	}
	for _, item := range c.Inbound {
		if !admitInbound(item) {
			return ErrUnsupported
		}
		if p.ManagedInput != nil {
			receiver, _ := item.ReceiverSettings.GetInstance()
			if receiver.(*proxyman.ReceiverConfig).PortList.Range[0].From == uint32(p.ManagedInput.Listen.Port()) {
				return ErrPolicy
			}
		}
	}
	return nil
}

// The pinned JSON builder migrates freedom UseIPv4 to a single DomainStrategy
// socket option. Caller traffic admits exactly that generated value; the native
// numeric resolver's selected egress still uses the unchanged strict gate.
func simpleFreedom(config *freedom.Config, sender *proxyman.SenderConfig, stream *internet.MemoryStreamConfig, policyEgress bool) bool {
	if policyEgress {
		return appoutbound.NativeDNSPolicyAllowsEgress(config, sender, stream)
	}
	if config.DomainStrategy != internet.DomainStrategy_USE_IP4 || stream == nil ||
		!proto.Equal(stream.SocketSettings, &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP4}) {
		return false
	}
	view := *stream
	view.SocketSettings = nil // Local validation view only; compiled source is untouched.
	return appoutbound.NativeDNSPolicyAllowsEgress(config, sender, &view)
}

func admitDNS(c *appdns.Config) bool {
	if c == nil || c.Script != "" || c.QueryStrategy == appdns.QueryStrategy_USE_SYS || c.QueryStrategy == appdns.QueryStrategy_USE_IP6 || len(c.NameServer) > 4 {
		return false
	}
	for _, s := range c.NameServer {
		if s == nil || s.QueryStrategy == appdns.QueryStrategy_USE_SYS || s.QueryStrategy == appdns.QueryStrategy_USE_IP6 || s.TimeoutMs > 4000 {
			return false
		}
	}
	// USE_IP and USE_IP4 remain exact source values. The native policy itself
	// supports IPv4; this preview does not certify general dual-stack DNS.
	return true
}

func admitInbound(item *core.InboundHandlerConfig) bool {
	if item == nil || item.ReceiverSettings == nil || item.ProxySettings == nil {
		return false
	}
	receiver, err := item.ReceiverSettings.GetInstance()
	if err != nil {
		return false
	}
	r, ok := receiver.(*proxyman.ReceiverConfig)
	if !ok || r.Listen == nil || r.ReceiveOriginalDestination || r.SniffingSettings != nil {
		return false
	}
	if !bytes.Equal(r.Listen.GetIp(), []byte{127, 0, 0, 1}) || r.PortList == nil || len(r.PortList.Range) != 1 {
		return false
	}
	port := r.PortList.Range[0]
	if port == nil || port.From == 0 || port.From != port.To || port.To > 65535 {
		return false
	}
	stream, err := internet.ToMemoryStreamConfig(r.StreamSettings)
	if err != nil || !appoutbound.NativeDNSPolicyAllowsEgress(&freedom.Config{}, nil, stream) {
		return false
	}
	proxy, err := item.ProxySettings.GetInstance()
	if err != nil {
		return false
	}
	s, ok := proxy.(*socks.ServerConfig)
	if !ok || s.AuthType != socks.AuthType_PASSWORD || s.UdpEnabled || s.Address != nil || len(s.Accounts) == 0 || len(s.Accounts) > 16 {
		return false
	}
	for user, password := range s.Accounts {
		if len(user) < 1 || len(user) > 255 || len(password) < 1 || len(password) > 255 {
			return false
		}
	}
	return true
}

func (p *Prepared) clone() (*core.Config, []internet.NativeDNSBinding, error) {
	if p == nil || p.blueprint == nil {
		return nil, nil, ErrDocument
	}
	c := proto.Clone(p.blueprint).(*core.Config)
	if p.policy.ManagedInput != nil {
		policy := p.policy.ManagedInput
		c.Inbound = append(c.Inbound, &core.InboundHandlerConfig{
			ReceiverSettings: commonserial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.IPAddress([]byte{127, 0, 0, 1})), PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(policy.Listen.Port()), To: uint32(policy.Listen.Port())}}}}),
			ProxySettings:    commonserial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{policy.Username: policy.Password}, UdpEnabled: true}),
		})
	}
	bindings := make([]internet.NativeDNSBinding, 0, len(c.Outbound))
	for index, item := range c.Outbound {
		plan, err := nativeconfig.AnalyzeOutbound(index, item)
		if err != nil {
			return nil, nil, ErrUnsupported
		}
		bindings = append(bindings, internet.NativeDNSBinding{Key: item, SourceIndex: index, Tag: item.Tag, ProxyType: plan.ProxyType})
	}
	return c, bindings, nil
}

func resolverDestination(p Policy) xnet.Destination {
	return xnet.TCPDestination(xnet.IPAddress(p.Resolver.Addr().AsSlice()), xnet.Port(p.Resolver.Port()))
}
