//go:build flutter_vless_core31_followups

package core31examples_test

// This is a real Core JSON Build contract, without constructing or starting
// Core. In particular the standalone Windows TUN example never opens an
// adapter, changes routes/DNS, or installs WFP filters in this test.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

var core31ExampleNames = []string{
	"geodat-gzip.json",
	"http-inbound-continue.json",
	"quic-direct-default.json",
	"quic-proxy-default.json",
	"windows-core-tun-leaks.json",
	"xhttp-h2params-server.json",
	"xhttp-options-client.json",
}

func core31ExampleCertificate(t *testing.T, directory string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(31),
		Subject: pkix.Name{CommonName: "core31-xhttp.invalid"}, DNSNames: []string{"core31-xhttp.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"core31-local-cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"core31-local-key.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		"geoip.dat":             []byte("owned existing geoip sentinel"),
		"geosite.dat":           []byte("owned existing geosite sentinel"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func core31ExampleFiles(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	result := map[string][32]byte{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatal("unexpected directory/symlink in owned example files", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = sha256.Sum256(data)
	}
	return result
}

func core31ExampleXHTTP(t *testing.T, stream *internet.StreamConfig) (*splithttp.Config, *xtls.Config) {
	t.Helper()
	if stream == nil || stream.ProtocolName != "splithttp" {
		t.Fatal("xhttp transport was not compiled")
	}
	var transport *splithttp.Config
	for _, setting := range stream.TransportSettings {
		if setting.ProtocolName != "splithttp" {
			continue
		}
		message, err := setting.Settings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		transport, _ = message.(*splithttp.Config)
	}
	var security *xtls.Config
	for _, setting := range stream.SecuritySettings {
		message, err := setting.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if value, ok := message.(*xtls.Config); ok {
			security = value
		}
	}
	if transport == nil || security == nil || transport.Path != "/core31" || transport.Mode != "packet-up" || !reflect.DeepEqual(security.NextProtocol, []string{"h2"}) {
		t.Fatal("xhttp/TLS example settings changed during Build")
	}
	return transport, security
}

func core31ExampleSemantics(t *testing.T, name string, built *core.Config) {
	t.Helper()
	if len(built.Inbound) != 1 || len(built.Outbound) == 0 {
		t.Fatal("example lost its inbound/outbound")
	}
	switch name {
	case "geodat-gzip.json":
		var found *geodata.Config
		for _, app := range built.App {
			message, err := app.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := message.(*geodata.Config); ok {
				found = value
			}
		}
		if found == nil || found.Cron != "0 4 * * *" || found.Outbound != "direct" || len(found.Assets) != 2 ||
			found.Assets[0].Url != "https://assets.example.test/geoip-compressed.bin" || found.Assets[0].File != "geoip.dat" ||
			found.Assets[1].Url != "https://assets.example.test/geosite.dat.gz" || found.Assets[1].File != "geosite.dat" {
			t.Fatal("GeoDAT example URLs/targets were not retained")
		}
	case "http-inbound-continue.json":
		message, err := built.Inbound[0].ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := message.(*httpproxy.ServerConfig); !ok {
			t.Fatal("HTTP example is not an HTTP inbound")
		}
	case "quic-direct-default.json", "quic-proxy-default.json":
		message, err := built.Inbound[0].ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		receiver, ok := message.(*proxyman.ReceiverConfig)
		if !ok || receiver.SniffingSettings == nil || !receiver.SniffingSettings.Enabled || !receiver.SniffingSettings.RouteOnly || !reflect.DeepEqual(receiver.SniffingSettings.DestinationOverride, []string{"quic"}) {
			t.Fatal("QUIC route-only sniffing was not retained")
		}
		defaultTag, ruleTag := "direct", "proxy"
		if name == "quic-proxy-default.json" {
			defaultTag, ruleTag = "proxy", "direct"
		}
		if built.Outbound[0].Tag != defaultTag {
			t.Fatal("QUIC default outbound order changed")
		}
		var found *router.Config
		for _, app := range built.App {
			message, err := app.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := message.(*router.Config); ok {
				found = value
			}
		}
		if found == nil || len(found.Rule) != 1 {
			t.Fatal("QUIC routing rule missing")
		}
		rule := found.Rule[0]
		if rule.GetTag() != ruleTag || !reflect.DeepEqual(rule.Networks, []xnet.Network{xnet.Network_UDP}) || len(rule.Domain) != 1 || rule.Domain[0].GetCustom() == nil || rule.Domain[0].GetCustom().Value != "quic-route.invalid" {
			t.Fatal("QUIC UDP domain routing target changed")
		}
	case "windows-core-tun-leaks.json":
		message, err := built.Inbound[0].ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		config, ok := message.(*tun.Config)
		if !ok || config.Name != "Core31-WFP-Example" || !reflect.DeepEqual(config.Gateway, []string{"198.18.31.1/30"}) || !reflect.DeepEqual(config.DNS, []string{"198.18.31.2"}) || !reflect.DeepEqual(config.AutoSystemRoutingTable, []string{"0.0.0.0/0"}) {
			t.Fatal("standalone Core TUN example settings changed")
		}
		for _, wanted := range []string{"tcp/853", "udp/853", "tcp/8443", "udp/8443"} {
			found := false
			for _, rule := range config.AutoSystemWfpBlockLeak {
				if rule == wanted {
					found = true
				}
			}
			if !found {
				t.Fatal("Core TUN leak port missing", wanted)
			}
		}
	case "xhttp-options-client.json":
		message, err := built.Outbound[0].SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sender, ok := message.(*proxyman.SenderConfig)
		if !ok {
			t.Fatal("XHTTP client sender settings missing")
		}
		transport, security := core31ExampleXHTTP(t, sender.StreamSettings)
		if transport.UplinkHTTPMethod != "OPTIONS" || security.ServerName != "core31-xhttp.invalid" || !security.DisableSystemRoot || len(security.Certificate) != 1 || security.Certificate[0].Usage != xtls.Certificate_AUTHORITY_VERIFY || len(security.Certificate[0].Certificate) == 0 {
			t.Fatal("OPTIONS or client authority lost from example extra settings")
		}
	case "xhttp-h2params-server.json":
		message, err := built.Inbound[0].ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		receiver, ok := message.(*proxyman.ReceiverConfig)
		if !ok {
			t.Fatal("XHTTP server receiver settings missing")
		}
		transport, security := core31ExampleXHTTP(t, receiver.StreamSettings)
		var settings struct{ MaxConcurrentStreams, MaxReadFrameSize int }
		if err := json.Unmarshal(transport.H2Params, &settings); err != nil {
			t.Fatal(err)
		}
		if settings.MaxConcurrentStreams != 7 || settings.MaxReadFrameSize != 32768 || len(security.Certificate) != 1 || len(security.Certificate[0].Certificate) == 0 || len(security.Certificate[0].Key) == 0 {
			t.Fatal("server h2Params or owned certificate lost from example extra settings")
		}
	default:
		t.Fatal("unqualified documented example", name)
	}
}

func TestCore31DocumentedExamplesBuild(t *testing.T) {
	if os.Getenv("CI") != "true" || runtime.GOOS == "darwin" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("Core31 example Build execution is CI-only")
	}
	directory, err := filepath.Abs(filepath.Join("testdata", "core31"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(core31ExampleNames) {
		t.Fatal("documented example set changed without updating the contract")
	}
	for index, name := range core31ExampleNames {
		if entries[index].Name() != name || !entries[index].Type().IsRegular() {
			t.Fatal("unexpected documented example entry")
		}
		t.Run(name, func(t *testing.T) {
			sourcePath := filepath.Join(directory, name)
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			owned := t.TempDir()
			core31ExampleCertificate(t, owned)
			before := core31ExampleFiles(t, owned)
			t.Chdir(owned)
			t.Setenv(platform.AssetLocation, owned)
			t.Setenv(platform.CertLocation, owned)
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(source))
			if err != nil {
				t.Fatal(err)
			}
			built, err := decoded.Build()
			if err != nil {
				t.Fatal(err)
			}
			core31ExampleSemantics(t, name, built)
			unchanged, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(source, unchanged) || !reflect.DeepEqual(before, core31ExampleFiles(t, owned)) {
				t.Fatal("example Build modified source or owned assets", err)
			}
			t.Logf("CORE31_EXAMPLE_BUILD_PASS name=%s semantics=true", name)
		})
	}
}
