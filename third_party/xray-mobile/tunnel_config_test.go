package XRay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// Validate actual Swift-produced JSON against the pinned core, without starting
// listeners, changing host routes, or making network requests.
func TestPreparedTunnelConfigs(t *testing.T) {
	directory := os.Getenv("TUNNEL_DNS_FIXTURES")
	if directory == "" {
		t.Skip("set TUNNEL_DNS_FIXTURES to the Swift regression fixture directory")
	}
	for _, name := range []string{"http", "socks", "aliases"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(directory, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			config, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.New(built)
			if err != nil {
				t.Fatal(err)
			}
			router := instance.GetFeature(routing.RouterType()).(routing.Router)
			for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
				for _, target := range []string{"2001:db8::42", "::ffff:192.0.2.42"} {
					// This is the routeOnly sniffing context: Target remains an IP
					// and RouteTarget carries the detected HTTP/TLS host.
					ctx := &routingsession.Context{
						Inbound: &session.Inbound{Tag: "socks-direct"},
						Outbound: &session.Outbound{
							Target:      net.Destination{Network: network, Address: net.ParseAddress(target), Port: 443},
							RouteTarget: net.TCPDestination(net.DomainAddress("control.example"), 443),
						},
					}
					route, err := router.PickRoute(ctx)
					if err != nil {
						t.Fatal(err)
					}
					// Xray normalizes IPv4-mapped addresses to IPv4; they cannot
					// represent an independent physical IPv6 destination.
					want := "flutter-vless-ipv6-block"
					if target == "::ffff:192.0.2.42" {
						want = "direct"
					}
					if route.GetOutboundTag() != want {
						t.Fatalf("%s routed to %s, want %s", target, route.GetOutboundTag(), want)
					}
				}
			}
			for _, tc := range []struct{ ip, tag, want string }{
				{"192.0.2.42", "socks-direct", "direct"},
				{"198.18.0.2", "socks-in", "flutter-vless-system-dns"},
				{"1.1.1.1", "flutter-vless-dns-upstream", "proxy"},
			} {
				route, err := router.PickRoute(&routingsession.Context{
					Inbound:  &session.Inbound{Tag: tc.tag},
					Outbound: &session.Outbound{Target: net.TCPDestination(net.ParseAddress(tc.ip), 53)},
				})
				if err != nil {
					t.Fatal(err)
				}
				if route.GetOutboundTag() != tc.want {
					t.Fatalf("%s routed to %s", tc.ip, route.GetOutboundTag())
				}
			}
			if err := instance.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
