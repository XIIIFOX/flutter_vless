package nativeconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/blackhole"
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/freedom"
	proxyhttp "github.com/xtls/xray-core/proxy/http"
	proxyhysteria "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/loopback"
	proxymasque "github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	vless "github.com/xtls/xray-core/proxy/vless/outbound"
	vmess "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/xdrive"
	"google.golang.org/protobuf/proto"
)

func nativeServer() *protocol.ServerEndpoint {
	return &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.DomainAddress("outer.example")), Port: 443}
}

func nativeSource(settings proto.Message, stream *internet.StreamConfig) *core.OutboundHandlerConfig {
	return &core.OutboundHandlerConfig{Tag: "private-tag-never-in-errors", ProxySettings: serial.ToTypedMessage(settings),
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: stream})}
}

func nativeStream(protocol string, settings proto.Message) *internet.StreamConfig {
	return &internet.StreamConfig{ProtocolName: protocol, TransportSettings: []*internet.TransportConfig{{ProtocolName: protocol, Settings: serial.ToTypedMessage(settings)}}}
}

func nativeTLS(stream *internet.StreamConfig, alpn ...string) *internet.StreamConfig {
	security := serial.ToTypedMessage(&tls.Config{NextProtocol: alpn, ServerName: "sni-is-not-an-endpoint.example"})
	stream.SecurityType, stream.SecuritySettings = security.Type, []*serial.TypedMessage{security}
	return stream
}

func hasRequirement(plan OutboundPlan, code RequirementCode) bool {
	for _, requirement := range plan.Requirements {
		if requirement.Code == code {
			return true
		}
	}
	return false
}

func TestNativeConfigAllOutboundIdentifiersCompileToTypedRoles(t *testing.T) {
	cases := []struct {
		name, family string
		settings     proto.Message
		role         Role
		stream       *internet.StreamConfig
		endpoints    int
	}{
		{"block", "blackhole", &blackhole.Config{}, RoleDrop, nil, 0},
		{"blackhole", "blackhole", &blackhole.Config{}, RoleDrop, nil, 0},
		{"direct", "freedom", &freedom.Config{}, RoleTarget, nil, 0},
		{"freedom", "freedom", &freedom.Config{}, RoleTarget, nil, 0},
		{"loopback", "loopback", &loopback.Config{InboundTag: "new-inbound"}, RoleDispatch, nil, 0},
		{"dns", "dns", &proxydns.Config{}, RoleDNS, nil, 0},
		{"http", "http", &proxyhttp.ClientConfig{Server: nativeServer()}, RoleEndpoint, nil, 1},
		{"shadowsocks", "shadowsocks", &shadowsocks.ClientConfig{Server: nativeServer()}, RoleEndpoint, nil, 1},
		{"socks", "socks", &socks.ClientConfig{Server: nativeServer()}, RoleEndpoint, nil, 1},
		{"vless", "vless", &vless.Config{Vnext: nativeServer()}, RoleEndpoint, nil, 1},
		{"vmess", "vmess", &vmess.Config{Receiver: nativeServer()}, RoleEndpoint, nil, 1},
		{"trojan", "trojan", &trojan.ClientConfig{Server: nativeServer()}, RoleEndpoint, nil, 1},
		{"hysteria", "hysteria", &proxyhysteria.ClientConfig{Server: nativeServer()}, RoleEndpoint, nativeStream("hysteria", &hysteria.Config{}), 1},
		{"masque", "masque", &proxymasque.ClientConfig{Server: nativeServer()}, RoleEndpoint, nativeTLS(nativeStream("masque", &masque.Config{}), "h2"), 1},
		{"wireguard", "wireguard", &wireguard.DeviceConfig{IsClient: true, Peers: []*wireguard.PeerConfig{{Endpoint: "first.example:51820"}, {Endpoint: "[2001:db8::1]:51821"}}}, RoleEndpoint, nil, 2},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := nativeSource(test.settings, test.stream)
			before := proto.Clone(source)
			plan, err := AnalyzeOutbound(index, source)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Source != source || plan.SourceIndex != index || plan.Family != test.family || plan.Role != test.role || len(plan.Endpoints) != test.endpoints {
				t.Fatalf("Incorrect typed role: family=%s role=%s endpoints=%d", plan.Family, plan.Role, len(plan.Endpoints))
			}
			if !proto.Equal(source, before) {
				t.Fatal("Caller compiled source changed")
			}
			if plan.Role == RoleTarget && !hasRequirement(plan, RequireDynamicTarget) {
				t.Fatal("Dynamic role omitted")
			}
			if plan.Role == RoleDispatch && !hasRequirement(plan, RequireRedispatch) {
				t.Fatal("Redispatch role omitted")
			}
			if plan.Role == RoleEndpoint && !hasRequirement(plan, RequireEndpointName) {
				t.Fatal("Endpoint preparation omitted")
			}
		})
	}
	for _, name := range []string{"direct", "DiReCt", "freedom", "block", "BlOcK", "blackhole"} {
		raw := json.RawMessage(`{}`)
		source, err := (&conf.OutboundDetourConfig{Protocol: name, Settings: &raw}).Build()
		if err != nil {
			t.Fatal(err)
		}
		plan, err := AnalyzeOutbound(0, source)
		if err != nil || (plan.Family != "freedom" && plan.Family != "blackhole") {
			t.Fatalf("Actual Core alias %s failed", name)
		}
	}
}

func TestNativeConfigEffectiveCompiledXHTTPPrecedenceAndDownload(t *testing.T) {
	var sourceJSON conf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"socks","settings":{"servers":[{"address":"upload.example","port":1080}]},"streamSettings":{"network":"tcp","method":"xhttp","address":"ignored-upload-override.example","port":9443,"xhttpSettings":{"mode":"stream-up","downloadSettings":{"address":"ignored-outer.example","port":443},"extra":{"downloadSettings":{"network":"splithttp","address":"download.example","port":8443,"xhttpSettings":{"downloadSettings":{"address":"unused-nested.example","port":9443}},"tlsSettings":{"alpn":["h3"]},"security":"tls","sockopt":{"dialerProxy":"download-chain"}}}},"splithttpSettings":{"downloadSettings":{"address":"ignored-alias.example","port":443}},"sockopt":{"dialerProxy":"upload-chain","penetrate":true,"addressPortStrategy":"srvportonly"}}}`), &sourceJSON); err != nil {
		t.Fatal(err)
	}
	compiled, err := sourceJSON.Build()
	if err != nil {
		t.Fatal(err)
	}
	before := proto.Clone(compiled)
	plan, err := AnalyzeOutbound(6, compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Endpoints) != 2 {
		t.Fatalf("Expected upload and effective extra download, got %d", len(plan.Endpoints))
	}
	upload, download := plan.Endpoints[0], plan.Endpoints[1]
	if upload.Transport != "splithttp" || upload.Physical.Address.String() != "upload.example" || upload.Physical.Port != 1080 {
		t.Fatal("Core method/alias precedence or non-override semantics changed")
	}
	if download.Role != EndpointDownload || download.Physical.Address.String() != "download.example" || download.Physical.Port != 8443 || download.Physical.Network != net.Network_UDP {
		t.Fatal("Actual XHTTP download/H3 destination not used")
	}
	if download.ChainTag != "upload-chain" || download.Socket == nil || !download.Socket.Penetrate {
		t.Fatal("Core penetrate inheritance not applied")
	}
	if !hasRequirement(plan, RequireServiceLookup) || !hasRequirement(plan, RequireDownload) || !hasRequirement(plan, RequireDatagram) {
		t.Fatal("Explicit runtime requirements missing")
	}
	if !proto.Equal(compiled, before) {
		t.Fatal("Caller compiled config changed")
	}
	download.Socket.DialerProxy = "mutated-plan"
	if !proto.Equal(compiled, before) {
		t.Fatal("Returned socket aliases caller config")
	}
	// Without penetrate, the download's own compiled socket settings win.
	value, _ := compiled.SenderSettings.GetInstance()
	sender := value.(*proxyman.SenderConfig)
	sender.StreamSettings.SocketSettings.Penetrate = false
	withoutPenetrate := proto.Clone(compiled).(*core.OutboundHandlerConfig)
	withoutPenetrate.SenderSettings = serial.ToTypedMessage(sender)
	separate, err := AnalyzeOutbound(6, withoutPenetrate)
	if err != nil || separate.Endpoints[1].ChainTag != "download-chain" {
		t.Fatal("Download's own socket policy lost without penetrate")
	}
}

func TestNativeConfigMasqueALPNAndXdriveFrontingAreDifferentRoles(t *testing.T) {
	for _, test := range []struct {
		alpn []string
		want net.Network
	}{{[]string{"h2"}, net.Network_TCP}, {[]string{"h3"}, net.Network_UDP}, {[]string{"h2", "h3"}, net.Network_UDP}, {nil, net.Network_UDP}} {
		plan, err := AnalyzeOutbound(2, nativeSource(&proxymasque.ClientConfig{Server: nativeServer()}, nativeTLS(nativeStream("masque", &masque.Config{}), test.alpn...)))
		if err != nil || plan.Endpoints[0].Physical.Network != test.want {
			t.Fatalf("MASQUE ALPN plan failed: %v", err)
		}
	}
	stream := nativeStream("xdrive", &xdrive.Config{Service: "service-is-not-an-endpoint", RemoteFolder: "private-control-data"})
	stream.Address, stream.Port = net.NewIPOrDomain(net.DomainAddress("front.example")), 9443
	plan, err := AnalyzeOutbound(9, nativeSource(&vless.Config{Vnext: nativeServer()}, stream))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := plan.Endpoints[0]
	if !endpoint.Dynamic || endpoint.Logical.Address.String() != "outer.example" || endpoint.Physical.Address.String() != "front.example" || endpoint.Physical.Port != 9443 || !hasRequirement(plan, RequireServiceEndpoint) {
		t.Fatal("XDRIVE service/fronting distinction lost")
	}
}

func TestNativeConfigLocalRolesDoNotInventProxyEndpoints(t *testing.T) {
	unknownStream := &internet.StreamConfig{ProtocolName: "not-a-registered-transport"}
	for _, settings := range []proto.Message{&blackhole.Config{}, &loopback.Config{InboundTag: "changed"}} {
		plan, err := AnalyzeOutbound(0, nativeSource(settings, unknownStream))
		if err != nil || len(plan.Endpoints) != 0 {
			t.Fatal("Non-dialing local role treated as physical proxy")
		}
	}
	plan, err := AnalyzeOutbound(1, nativeSource(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.DomainAddress("override.example"))}}}, nil))
	if err != nil || len(plan.Endpoints) != 1 || !plan.Endpoints[0].Dynamic || plan.Endpoints[0].Physical.Port != 0 || hasRequirement(plan, RequireEndpointName) {
		t.Fatal("Partial runtime override became a physical bootstrap endpoint")
	}
}

func TestNativeConfigErrorsHaveOnlySafeSourceAndRole(t *testing.T) {
	for _, test := range []struct {
		source *core.OutboundHandlerConfig
		code   ErrorCode
	}{
		{nil, InvalidSource},
		{nativeSource(&proxyman.ReceiverConfig{}, nil), UnsupportedRole},
		{nativeSource(&socks.ClientConfig{}, nil), InvalidEndpoint},
		{nativeSource(&socks.ClientConfig{Server: nativeServer()}, &internet.StreamConfig{ProtocolName: "private-unsupported-name"}), InvalidCompiled},
		{nativeSource(&wireguard.DeviceConfig{IsClient: true, Peers: []*wireguard.PeerConfig{{Endpoint: "private-malformed-peer"}}}, nil), InvalidEndpoint},
	} {
		_, err := AnalyzeOutbound(11, test.source)
		var safe *SourceError
		if !errors.As(err, &safe) || safe.SourceIndex != 11 || safe.Code != test.code {
			t.Fatalf("Wrong safe source error: %v", err)
		}
		if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "outer.example") {
			t.Fatal("Private source data leaked in error")
		}
	}
}

func TestNativeConfigActualFreedomPartialOverridesRemainDynamic(t *testing.T) {
	for _, test := range []struct {
		redirect, host string
		port           net.Port
	}{
		{":8443", "", 8443}, {":0", "", 0}, {"override.example:0", "override.example", 0},
		{"0.0.0.0:8443", "", 8443}, {"[::]:8443", "", 8443},
	} {
		raw, _ := json.Marshal(map[string]string{"redirect": test.redirect})
		settings := json.RawMessage(raw)
		source, err := (&conf.OutboundDetourConfig{Protocol: "freedom", Settings: &settings}).Build()
		if err != nil {
			t.Fatal(err)
		}
		before := proto.Clone(source)
		plan, err := AnalyzeOutbound(3, source)
		if err != nil || len(plan.Endpoints) != 1 {
			t.Fatalf("Partial override rejected: %v", err)
		}
		override := plan.Endpoints[0]
		host := ""
		if override.Physical.Address != nil {
			host = override.Physical.Address.String()
		}
		if override.Role != EndpointOverride || !override.Dynamic || host != test.host || override.Physical.Port != test.port || hasRequirement(plan, RequireEndpointName) {
			t.Fatal("Runtime override became a fixed physical endpoint")
		}
		if !proto.Equal(source, before) {
			t.Fatal("Partial redirect mutated caller source")
		}
	}
	_, err := AnalyzeOutbound(3, nativeSource(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Port: 65536}}}, nil))
	var safe *SourceError
	if !errors.As(err, &safe) || safe.Code != InvalidEndpoint {
		t.Fatal("Out of range redirect port accepted")
	}
}

func TestNativeConfigActualShadowsocksConditionalCompiledTypes(t *testing.T) {
	for _, test := range []struct{ method, password, proxyType string }{
		{"aes-128-gcm", "synthetic-test-password", "xray.proxy.shadowsocks.ClientConfig"},
		{"2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==", "xray.proxy.shadowsocks_2022.ClientConfig"},
	} {
		raw, _ := json.Marshal(map[string]any{"address": "ss.example", "port": 443, "method": test.method, "password": test.password})
		settings := json.RawMessage(raw)
		source, err := (&conf.OutboundDetourConfig{Protocol: "shadowsocks", Settings: &settings}).Build()
		if err != nil {
			t.Fatal(err)
		}
		before := proto.Clone(source)
		plan, err := AnalyzeOutbound(4, source)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Family != "shadowsocks" || plan.Role != RoleEndpoint || plan.ProxyType != test.proxyType || len(plan.Endpoints) != 1 || plan.Endpoints[0].Physical.Address.String() != "ss.example" || plan.Endpoints[0].Physical.Port != 443 {
			t.Fatal("Conditional compiled Shadowsocks endpoint type lost")
		}
		if !proto.Equal(source, before) {
			t.Fatal("Conditional Shadowsocks source changed")
		}
	}
}

func TestNativeConfigActualDNSPartialRewritesAreNotFixedEndpoints(t *testing.T) {
	for _, test := range []struct {
		settings string
		dynamic  bool
	}{
		{`{}`, true}, {`{"rewriteNetwork":"tcp"}`, true}, {`{"rewritePort":53}`, true},
		{`{"rewriteNetwork":"tcp","rewriteAddress":"resolver.example"}`, true},
		{`{"rewriteNetwork":"tcp","rewriteAddress":"resolver.example","rewritePort":53}`, false},
	} {
		raw := json.RawMessage(test.settings)
		source, err := (&conf.OutboundDetourConfig{Protocol: "dns", Settings: &raw}).Build()
		if err != nil {
			t.Fatal(err)
		}
		before := proto.Clone(source)
		plan, err := AnalyzeOutbound(5, source)
		if err != nil || len(plan.Endpoints) != 1 || plan.Endpoints[0].Role != EndpointDNS || plan.Endpoints[0].Dynamic != test.dynamic {
			t.Fatal("Partial DNS rewrite became a complete fixed endpoint")
		}
		if !proto.Equal(source, before) {
			t.Fatal("Caller DNS outbound changed")
		}
	}
}
