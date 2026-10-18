package outbound_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	proxyoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
)

// Exercise the actual pinned JSON decoder/build/memory transport normalization,
// without creating Core, a proxy worker or any socket.
func TestNativeDNSSimplePolicyEgressUsesCompiledSettings(t *testing.T) {
	for _, item := range []struct {
		source  string
		allowed bool
	}{
		{`{"protocol":"freedom"}`, true},
		{`{"protocol":"freedom","streamSettings":{"network":"tcp"}}`, true},
		{`{"protocol":"freedom","streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":["/"]}}}}}`, false},
		{`{"protocol":"freedom","streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}`, false},
		{`{"protocol":"freedom","streamSettings":{"network":"ws"}}`, false},
		{`{"protocol":"freedom","streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.invalid"}}}`, false},
		{`{"protocol":"freedom","settings":{"redirect":"127.0.0.1:5353"}}`, false},
		{`{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}`, false},
		{`{"protocol":"freedom","sendThrough":"127.0.0.1"}`, false},
		{`{"protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"other"}}}`, false},
		{`{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":5353}]}}`, false},
	} {
		t.Run(item.source, func(t *testing.T) {
			var config conf.OutboundDetourConfig
			if err := json.Unmarshal([]byte(item.source), &config); err != nil {
				t.Fatal(err)
			}
			compiled, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			proxyConfig, err := compiled.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			var sender *proxyman.SenderConfig
			var stream *internet.MemoryStreamConfig
			if compiled.SenderSettings != nil {
				raw, err := compiled.SenderSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				sender = raw.(*proxyman.SenderConfig)
				stream, err = internet.ToMemoryStreamConfig(sender.StreamSettings)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := proxyoutbound.NativeDNSPolicyAllowsEgress(proxyConfig, sender, stream); got != item.allowed {
				t.Fatalf("allowed=%v want=%v", got, item.allowed)
			}
		})
	}
}
