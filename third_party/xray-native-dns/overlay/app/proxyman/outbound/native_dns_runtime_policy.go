package outbound

import (
	"github.com/xtls/xray-core/app/proxyman"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/protobuf/proto"
)

// Validate and freeze membership under the exact Add/Remove admission lock.
func (m *Manager) SealNativeDNSHandlers(expected []featureoutbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.nativeDNSSealed || m.running || len(expected) != len(m.taggedHandler)+len(m.untaggedHandlers) {
		return internet.ErrNativeDNSIdentity
	}
	seen := make(map[featureoutbound.Handler]bool, len(expected))
	for _, handler := range expected {
		if handler == nil || seen[handler] {
			return internet.ErrNativeDNSIdentity
		}
		seen[handler] = true
	}
	for _, handler := range m.taggedHandler {
		if !seen[handler] {
			return internet.ErrNativeDNSIdentity
		}
	}
	for _, handler := range m.untaggedHandlers {
		if !seen[handler] {
			return internet.ErrNativeDNSIdentity
		}
	}
	m.nativeDNSSealed = true
	return nil
}

// First protected-default preview admits a simple direct TCP egress only.
// Caller remote-DNS clients keep their original router/handler paths. Proxy,
// mux/chaining and rewritten destinations require separate qualification.
func (h *Handler) NativeDNSPolicyEgressAllowed() bool {
	return h.mux == nil && h.xudp == nil && NativeDNSPolicyAllowsEgress(h.proxyConfig, h.senderSettings, h.streamSettings)
}

// Pure compiled-settings gate, shared by construction acceptance tests. It does
// not create handlers, start Core, or resolve/dial anything.
func NativeDNSPolicyAllowsEgress(proxyConfig proto.Message, sender *proxyman.SenderConfig, stream *internet.MemoryStreamConfig) bool {
	config, ok := proxyConfig.(*freedom.Config)
	if !ok || config == nil || config.DestinationOverride != nil || config.Fragment != nil ||
		config.ProxyProtocol != 0 || len(config.Noises) != 0 || len(config.FinalRules) != 0 {
		return false
	}
	if sender != nil && (sender.Via != nil || sender.ViaCidr != "" || sender.MultiplexSettings.GetEnabled()) {
		return false
	}
	if stream != nil && (stream.ProtocolName != "tcp" || stream.SecurityType != "" ||
		stream.Destination != nil || stream.FinalMask != nil || stream.QuicParams != nil ||
		stream.DownloadSettings != nil || stream.SocketSettings != nil) {
		return false
	}
	if stream != nil {
		settings, ok := stream.ProtocolSettings.(*tcp.Config)
		if !ok || settings == nil || settings.HeaderSettings != nil || settings.AcceptProxyProtocol {
			return false
		}
	}
	return true
}
