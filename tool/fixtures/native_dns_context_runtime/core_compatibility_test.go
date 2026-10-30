package native_dns_context_runtime_test

// Configuration-only checks against the actual pinned Core. No Core instance,
// resolver, listener, system route or VPN is created by this test.
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

func TestAcceptanceCoreCompatibility(t *testing.T) {
	t.Run("private-routing-is-not-transport-trust", func(t *testing.T) {
		cases := []struct {
			address                          string
			routingPrivate, plaintextAllowed bool
		}{
			{"10.1.2.3", true, true}, {"172.16.0.1", true, true},
			{"192.168.1.1", true, true}, {"127.0.0.1", true, true},
			{"169.254.1.1", true, true}, {"::1", true, true},
			{"fd12::1", true, true}, {"fe80::1", true, true},
			{"100.64.0.1", true, false}, {"192.0.2.1", true, false},
			{"198.18.0.1", true, false}, {"192.0.0.170", true, false},
			{"64:ff9b::808:808", true, false}, {"64:ff9b::a00:1", true, false},
			{"64:ff9b:1::1", true, false}, {"2001:db8::1", true, false},
			{"3fff::1", true, false}, {"224.0.0.1", true, false},
			{"1.1.1.1", false, false}, {"2606:4700:4700::1111", false, false},
		}
		for _, row := range cases {
			t.Run(row.address, func(t *testing.T) {
				if actual := geodata.GetPrivateIPMatcher().Match(xnet.ParseAddress(row.address).IP()); actual != row.routingPrivate {
					t.Fatalf("generalized private routing: got %v want %v", actual, row.routingPrivate)
				}
				for _, protocol := range []string{"vless", "trojan"} {
					for _, tls := range []bool{false, true} {
						settings := map[string]any{"address": row.address, "port": 443, "id": "00000000-0000-4000-8000-000000000001", "encryption": "none"}
						if protocol == "trojan" {
							settings = map[string]any{"servers": []any{map[string]any{"address": row.address, "port": 443, "password": "fixture-only"}}}
						}
						outbound := map[string]any{"protocol": protocol, "settings": settings}
						if tls {
							outbound["streamSettings"] = map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "fixture.example"}}
						}
						encoded, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
						if err != nil {
							t.Fatal(err)
						}
						_, err = core.LoadConfig("json", bytes.NewReader(encoded))
						allowed := tls || row.plaintextAllowed
						if allowed && err != nil {
							t.Fatalf("%s TLS=%v unexpectedly refused: %v", protocol, tls, err)
						}
						if !allowed && (err == nil || !strings.Contains(err.Error(), "without TLS")) {
							t.Fatalf("%s untrusted plaintext must fail transport-security validation: %v", protocol, err)
						}
					}
				}
			})
		}
	})
	t.Run("documented-finalmask-migration", func(t *testing.T) {
		load := func(name string) *core.Config {
			t.Helper()
			data, err := os.ReadFile(filepath.Join("native_dns_context_runtime", "testdata", "finalmask", name))
			if err != nil {
				t.Fatal(err)
			}
			c, err := core.LoadConfig("json", bytes.NewReader(data))
			if err != nil {
				t.Fatalf("documented %s rejected: %v", name, err)
			}
			return c
		}
		legacy := load("legacy-freedom.json")
		modern := load("finalmask.json")
		oldMessage, err := legacy.Outbound[0].ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		old := oldMessage.(*freedom.Config)
		senderMessage, err := modern.Outbound[0].SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		stream := senderMessage.(*proxyman.SenderConfig).StreamSettings
		if len(stream.GetTcpmasks()) != 1 || len(stream.GetUdpmasks()) != 1 {
			t.Fatal("documented masks lost during Core compilation")
		}
		fragMessage, err := stream.GetTcpmasks()[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		frag := fragMessage.(*fragment.Config)
		if len(frag.LengthsMin) != 1 || len(frag.LengthsMax) != 1 || len(frag.DelaysMin) != 1 || len(frag.DelaysMax) != 1 {
			t.Fatal("fragment ranges missing")
		}
		if frag.PacketsFrom != int64(old.Fragment.PacketsFrom) || frag.PacketsTo != int64(old.Fragment.PacketsTo) ||
			frag.LengthsMin[0] != int64(old.Fragment.LengthMin) || frag.LengthsMax[0] != int64(old.Fragment.LengthMax) ||
			frag.DelaysMin[0] != int64(old.Fragment.IntervalMin) || frag.DelaysMax[0] != int64(old.Fragment.IntervalMax) {
			t.Fatal("legacy interval/length/packet semantics not represented by new example")
		}
		noiseMessage, err := stream.GetUdpmasks()[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		mask := noiseMessage.(*noise.Config)
		if len(old.Noises) != 1 || len(mask.Items) != 1 {
			t.Fatal("noise item lost")
		}
		item, previous := mask.Items[0], old.Noises[0]
		if item.RandMin != int64(previous.LengthMin) || item.RandMax != int64(previous.LengthMax) || item.DelayMin != int64(previous.DelayMin) || item.DelayMax != int64(previous.DelayMax) {
			t.Fatal("noise random/delay ranges changed")
		}
		if mask.ResetMin != 0 || mask.ResetMax != 0 || previous.ApplyTo != "ip" {
			t.Fatal("documented all-family/no-reset policy changed")
		}
	})
}
