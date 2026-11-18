//go:build flutter_vless_balancer_diagnostics

package XRay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestPrivateBalancerDiagnosticsRuntime(t *testing.T) {
	if BalancerDiagnosticsCapability() != 1 {
		t.Fatal("missing balancer diagnostics ABI")
	}
	for _, scenario := range []struct {
		label           string
		useRouting, cli bool
		managedIndex    int
	}{
		{label: "ordinary private runtime"},
		{label: "private routing runtime", useRouting: true},
		{label: "CLI after imported inbounds", cli: true, managedIndex: 1},
		{label: "CLI routing after imported inbounds", useRouting: true, cli: true, managedIndex: 1},
	} {
		useRouting := scenario.useRouting
		if useRouting && RoutingCapability() == 0 {
			continue
		}
		t.Run(scenario.label, func(t *testing.T) {
			t.Cleanup(Stop)
			first := balancerDiagnosticsOrigin(t, "A")
			second := balancerDiagnosticsOrigin(t, "B")
			managedAddr := reserveBalancerAddress(t)
			importedAddr := reserveBalancerAddress(t)
			const managedTag = "private-inbound-marker"
			auth := &proxy.Auth{User: "private-user-marker", Password: "private-password-marker"}
			managed := balancerDiagnosticsInbound(t, managedAddr, managedTag, auth)
			imported := balancerDiagnosticsInbound(t, importedAddr, "imported", nil)
			inbounds := []any{managed, imported}
			if scenario.managedIndex == 1 {
				inbounds[0], inbounds[1] = inbounds[1], inbounds[0]
			}
			start := StartBalancerDiagnosticsPrivate
			if scenario.cli {
				start = StartCLIBalancerDiagnosticsPrivate
			}
			const nodeA, nodeB, group = "private-node-a", "private-node-b", "private-group-marker"
			const target, direct = "private-destination.invalid", "standalone-rule.invalid"
			config, err := json.Marshal(map[string]any{
				"log":       map[string]any{"loglevel": "none"},
				"inbounds":  inbounds,
				"outbounds": []any{balancerDiagnosticsOutbound(nodeA, first), balancerDiagnosticsOutbound(nodeB, second)},
				"routing": map[string]any{
					"balancers": []any{map[string]any{"tag": group, "selector": []string{nodeA, nodeB}, "strategy": map[string]any{"type": "roundRobin"}}},
					"rules": []any{
						map[string]any{"type": "field", "domain": []string{"full:" + direct}, "outboundTag": nodeA},
						map[string]any{"type": "field", "network": "tcp", "balancerTag": group},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var spec []byte
			if useRouting {
				digest := sha256.Sum256(config)
				spec, err = json.Marshal(map[string]any{"version": 1, "source_sha256": hex.EncodeToString(digest[:]),
					"managed_inbound_index": scenario.managedIndex, "managed_inbound_tag": managedTag,
					"auth_user": auth.User, "source_inbound_index": 1 - scenario.managedIndex})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := start(config, spec, managedTag, 3, nil); err != nil {
				t.Fatal(err)
			}
			client := balancerDiagnosticsClient(t, managedAddr, auth)
			for index, expected := range []string{"A", "B", "A", "B"} {
				checkBalancerDiagnosticsOrigin(t, client, target, expected, index+1)
			}
			const boundedHistory = "2,1,2\n3,1,1\n4,1,2\n"
			if got := ReadBalancerDiagnostics(); got != boundedHistory {
				t.Fatalf("wrong bounded, numeric-only dispatch history: %q", got)
			}
			// A direct rule that targets a group member must not count, nor may
			// another inbound getting routed to the same balancer be observed.
			checkBalancerDiagnosticsOrigin(t, client, direct, "A", 5)
			foreign := balancerDiagnosticsClient(t, importedAddr, nil)
			checkBalancerDiagnosticsOrigin(t, foreign, target, "A", 6)
			if got := ReadBalancerDiagnostics(); got != boundedHistory {
				t.Fatalf("non-balancer traffic or a foreign inbound reached the history: %q", got)
			}
			DisableBalancerDiagnostics()
			checkBalancerDiagnosticsOrigin(t, client, target, "B", 7)
			if got := ReadBalancerDiagnostics(); got != "" {
				t.Fatal("history was recorded after live opt-out")
			}
			Stop()
			if got := ReadBalancerDiagnostics(); got != "" {
				t.Fatal("history survived Stop")
			}
			if err := start(config, spec, managedTag, 0, nil); err != nil {
				t.Fatal(err)
			}
			checkBalancerDiagnosticsOrigin(t, client, target, "A", 1)
			if got := ReadBalancerDiagnostics(); got != "" {
				t.Fatal("history appeared with collection disabled")
			}
		})
	}
}

func balancerDiagnosticsOrigin(t *testing.T, marker string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func reserveBalancerAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func balancerDiagnosticsInbound(t *testing.T, address, tag string, auth *proxy.Auth) map[string]any {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"auth": "noauth"}
	if auth != nil {
		settings = map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": auth.User, "pass": auth.Password}}}
	}
	return map[string]any{"tag": tag, "listen": "127.0.0.1", "port": addr.Port, "protocol": "socks", "settings": settings}
}

func balancerDiagnosticsOutbound(tag, destination string) map[string]any {
	return map[string]any{"tag": tag, "protocol": "freedom", "settings": map[string]any{"redirect": destination}}
}

func balancerDiagnosticsClient(t *testing.T, address string, auth *proxy.Auth) *http.Client {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", address, auth, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func checkBalancerDiagnosticsOrigin(t *testing.T, client *http.Client, target, expected string, attempt int) {
	t.Helper()
	response, err := client.Get("http://" + target)
	if err != nil {
		t.Fatalf("request %d: %v", attempt, err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || string(got) != expected {
		t.Fatalf("request %d: reached %q, want %q (err %v)", attempt, got, expected, err)
	}
}
