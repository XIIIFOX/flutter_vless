package native_dns_context_runtime_test

// CI-only real Core acceptance. No fixture relays outside loopback, performs a
// system DNS lookup, or changes routes/DNS/VPN. Merely compiling is safe locally.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/nativeconfig"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

const endpointHost = "same-endpoint.invalid"

type loopServer struct {
	listener net.Listener
	lock     sync.Mutex
	active   map[net.Conn]struct{}
	observed []string
	errors   []string
	wait     sync.WaitGroup
}

func newLoopServer(t *testing.T, network, address string, serve func(*loopServer, net.Conn) error) *loopServer {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("Required loopback listener unavailable: %v", err)
	}
	server := &loopServer{listener: listener, active: map[net.Conn]struct{}{}}
	server.wait.Add(1)
	go func() {
		defer server.wait.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.lock.Lock()
			server.active[conn] = struct{}{}
			server.wait.Add(1)
			server.lock.Unlock()
			go func() {
				defer server.wait.Done()
				defer conn.Close()
				defer func() { server.lock.Lock(); delete(server.active, conn); server.lock.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := serve(server, conn); err != nil {
					server.lock.Lock()
					server.errors = append(server.errors, err.Error())
					server.lock.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		server.lock.Lock()
		for conn := range server.active {
			_ = conn.Close()
		}
		server.lock.Unlock()
		finished := make(chan struct{})
		go func() { server.wait.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(7 * time.Second):
			t.Error("Owned fixture connections did not close within deadline")
		}
	})
	return server
}

func (server *loopServer) record(value string) {
	server.lock.Lock()
	defer server.lock.Unlock()
	server.observed = append(server.observed, value)
}

func (server *loopServer) observations() ([]string, []string) {
	server.lock.Lock()
	defer server.lock.Unlock()
	return append([]string(nil), server.observed...), append([]string(nil), server.errors...)
}

// The same-port IPv4/IPv6 fixtures speak SOCKS to proxy transports and plain
// HTTP to caller freedom. SOCKS CONNECT never resolves/relays its destination.
func markerProtocol(proxyMarker, directMarker string) func(*loopServer, net.Conn) error {
	return func(server *loopServer, conn net.Conn) error {
		reader := bufio.NewReader(conn)
		first, err := reader.Peek(1)
		if err != nil {
			return err
		}
		marker := directMarker
		if first[0] == 5 {
			var greeting [2]byte
			if _, err := io.ReadFull(reader, greeting[:]); err != nil {
				return err
			}
			methods := make([]byte, int(greeting[1]))
			if _, err := io.ReadFull(reader, methods); err != nil {
				return err
			}
			if !bytes.Contains(methods, []byte{0}) {
				return fmt.Errorf("Fixture requires SOCKS noauth")
			}
			if _, err := conn.Write([]byte{5, 0}); err != nil {
				return err
			}
			var request [4]byte
			if _, err := io.ReadFull(reader, request[:]); err != nil {
				return err
			}
			if request != [4]byte{5, 1, 0, 3} {
				return fmt.Errorf("SOCKS target was rewritten/resolved instead of carried as domain")
			}
			length, err := reader.ReadByte()
			if err != nil {
				return err
			}
			host := make([]byte, int(length))
			if _, err := io.ReadFull(reader, host); err != nil {
				return err
			}
			var port uint16
			if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
				return err
			}
			if string(host) != "remote-marker.invalid" || port != 80 {
				return fmt.Errorf("Unexpected proxy target; DNS tag route may have been lost")
			}
			server.record("SOCKS " + string(host) + ":80")
			if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
				return err
			}
			marker = proxyMarker
		}
		request, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		defer request.Body.Close()
		server.record("HTTP " + request.Host)
		_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(marker), marker)
		return err
	}
}

func dnsProtocol(expectedHost, answer string, expectedType uint16) func(*loopServer, net.Conn) error {
	return func(server *loopServer, conn net.Conn) error {
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return err
		}
		if length > 4096 || length == 0 {
			return fmt.Errorf("Invalid bounded DNS message size")
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return err
		}
		query := &wireDNS.Msg{}
		if err := query.Unpack(packet); err != nil {
			return err
		}
		if len(query.Question) != 1 {
			return fmt.Errorf("Expected exactly one DNS question")
		}
		question := query.Question[0]
		server.record(fmt.Sprintf("%s %d", question.Name, question.Qtype))
		response := &wireDNS.Msg{}
		response.SetReply(query)
		if question.Name != expectedHost+"." || question.Qtype != expectedType {
			response.Rcode = wireDNS.RcodeRefused
		} else {
			header := wireDNS.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: wireDNS.ClassINET, Ttl: 1}
			if expectedType == wireDNS.TypeA {
				response.Answer = []wireDNS.RR{&wireDNS.A{Hdr: header, A: net.ParseIP(answer)}}
			} else {
				response.Answer = []wireDNS.RR{&wireDNS.AAAA{Hdr: header, AAAA: net.ParseIP(answer)}}
			}
		}
		result, err := response.Pack()
		if err != nil {
			return err
		}
		if err := binary.Write(conn, binary.BigEndian, uint16(len(result))); err != nil {
			return err
		}
		_, err = conn.Write(result)
		return err
	}
}

type ownedCore struct {
	owner      *internet.NativeDNSOwner
	core       *core.Instance
	config     *core.Config
	dnsApp     []byte
	tags       []string
	closed     sync.Once
	closeError error
}

func (engine *ownedCore) close() error {
	engine.closed.Do(func() {
		_ = engine.owner.Close()
		engine.closeError = engine.core.Close()
	})
	return engine.closeError
}

func makeConfig(t *testing.T, endpointPort int, alpha, beta *loopServer, withDNS bool, callerHostIP string) (*core.Config, []byte) {
	t.Helper()
	configuration := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"outbounds": []any{
			map[string]any{"protocol": "socks", "tag": "caller-proxy", "settings": map[string]any{"servers": []any{map[string]any{"address": endpointHost, "port": endpointPort}}}},
			map[string]any{"protocol": "freedom", "tag": "caller-direct", "settings": map[string]any{"domainStrategy": "UseIP"}},
			map[string]any{"protocol": "freedom", "tag": "caller-dns-alpha"},
			map[string]any{"protocol": "freedom", "tag": "caller-dns-beta"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"dns-alpha"}, "outboundTag": "caller-dns-alpha"},
			map[string]any{"type": "field", "inboundTag": []string{"dns-beta"}, "outboundTag": "caller-dns-beta"},
			map[string]any{"type": "field", "domain": []string{"full:" + endpointHost, "full:alpha.invalid", "full:beta.invalid"}, "outboundTag": "caller-direct"},
		}},
	}
	if withDNS {
		configuration["dns"] = map[string]any{
			"hosts": map[string]any{endpointHost: callerHostIP}, "queryStrategy": "UseIP",
			"disableCache": true, "disableFallbackIfMatch": true,
			"servers": []any{
				map[string]any{"address": "tcp://" + alpha.listener.Addr().String(), "domains": []string{"full:alpha.invalid"}, "queryStrategy": "UseIPv4", "tag": "dns-alpha", "skipFallback": true, "timeoutMs": 1500},
				map[string]any{"address": "tcp://" + beta.listener.Addr().String(), "domains": []string{"full:beta.invalid"}, "queryStrategy": "UseIPv6", "tag": "dns-beta", "skipFallback": true, "timeoutMs": 1500},
			},
		}
	}
	serialized, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := core.LoadConfig("json", bytes.NewReader(serialized))
	if err != nil {
		t.Fatal(err)
	}
	var dnsApp []byte
	for _, app := range compiled.App {
		if app.Type == "xray.app.dns.Config" {
			dnsApp = append([]byte(nil), app.Value...)
		}
	}
	if withDNS && len(dnsApp) == 0 {
		t.Fatal("Compiled caller DNS was not found")
	}
	plan, err := nativeconfig.AnalyzeRootDNS(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if nativeconfig.ValidateRootDNSCapabilities(plan, nil) == nil {
		t.Fatal("Caller DNS accepted without explicit fixture capability")
	}
	gateError := nativeconfig.ValidateRootDNSCapabilities(plan, map[nativeconfig.RootDNSCapability]bool{nativeconfig.DNSRemoteTCP: true})
	if withDNS {
		if gateError != nil || len(plan.Requirements) != 2 {
			t.Fatal("Numeric remote TCP fixture requires only explicit remote-TCP capability")
		}
	} else {
		if gateError == nil || len(plan.Requirements) != 1 || plan.Requirements[0].Capability != nativeconfig.DNSLocalSystem {
			t.Fatal("No-DNS factory case must remain rejected as protected usable DNS")
		}
	}
	return compiled, dnsApp
}

func startOwner(t *testing.T, config *core.Config, dnsApp []byte, pin string, port int) *ownedCore {
	t.Helper()
	bindings := make([]internet.NativeDNSBinding, len(config.Outbound))
	tags := make([]string, len(config.Outbound))
	for index, outbound := range config.Outbound {
		tags[index] = outbound.Tag
		bindings[index] = internet.NativeDNSBinding{Key: outbound, SourceIndex: index, Tag: outbound.Tag, ProxyType: outbound.ProxySettings.Type}
		if index == 0 {
			bindings[index].TransportEndpoints = true
			bindings[index].Endpoints = []internet.NativeDNSEndpoint{{Network: xnet.Network_TCP, Host: endpointHost, Port: xnet.Port(port), Addresses: []netip.Addr{netip.MustParseAddr(pin)}}}
		}
	}
	owner, err := internet.NewNativeDNSOwner(bindings)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.NewWithContext(internet.ContextWithNativeDNSOwner(context.Background(), owner), config)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("Actual Core construction failed: %v", err)
	}
	engine := &ownedCore{owner: owner, core: instance, config: config, dnsApp: dnsApp, tags: tags}
	t.Cleanup(func() {
		if err := engine.close(); err != nil {
			t.Errorf("Core close failed: %v", err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatalf("Actual Core start failed: %v", err)
	}
	return engine
}

func fetchMarker(engine *ownedCore, host string, port int) (string, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		host, textPort, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(textPort)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, engine.core, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/native-dns-marker")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return "", err
	}
	if response.StatusCode != 200 {
		return "", fmt.Errorf("Unexpected HTTP status %d", response.StatusCode)
	}
	return string(body), nil
}

func marker(t *testing.T, engine *ownedCore, host string, port int, expected string) {
	t.Helper()
	body, err := fetchMarker(engine, host, port)
	if err != nil || body != expected {
		t.Fatalf("Wrong HTTP owner/caller marker: want=%s body=%q error=%v", expected, body, err)
	}
}

func sourceUnchanged(t *testing.T, engine *ownedCore) {
	t.Helper()
	for index, outbound := range engine.config.Outbound {
		if outbound.Tag != engine.tags[index] {
			t.Fatal("Caller outbound tag was rewritten")
		}
	}
	for _, app := range engine.config.App {
		if app.Type == "xray.app.dns.Config" && !bytes.Equal(engine.dnsApp, app.Value) {
			t.Fatal("Caller compiled root DNS source was changed")
		}
	}
}

func TestAcceptanceNativeDNSRuntime(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || (runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true")) {
		t.Fatal("Real Core runtime acceptance is CI-only; Darwin additionally requires GitHub Actions")
	}
	var externalDNSAttempts atomic.Int64
	previousStandard, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		externalDNSAttempts.Add(1)
		return nil, errors.New("System DNS is forbidden in this loopback fixture")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previousStandard, previousCore
		if count := externalDNSAttempts.Load(); count != 0 {
			t.Errorf("System resolver attempted %d DNS dials", count)
		}
	})
	t.Log("PHASE loopback fixtures: start")
	v4 := newLoopServer(t, "tcp4", "127.0.0.1:0", markerProtocol("OWNER_B", "CALLER_V4"))
	port := v4.listener.Addr().(*net.TCPAddr).Port
	v6 := newLoopServer(t, "tcp6", net.JoinHostPort("::1", strconv.Itoa(port)), markerProtocol("OWNER_A", "CALLER_V6"))
	alpha := newLoopServer(t, "tcp4", "127.0.0.1:0", dnsProtocol("alpha.invalid", "127.0.0.1", wireDNS.TypeA))
	beta := newLoopServer(t, "tcp4", "127.0.0.1:0", dnsProtocol("beta.invalid", "::1", wireDNS.TypeAAAA))
	configA, dnsA := makeConfig(t, port, alpha, beta, true, "127.0.0.1")
	configB, dnsB := makeConfig(t, port, alpha, beta, true, "::1")
	if bytes.Equal(dnsA, dnsB) {
		t.Fatal("Caller DNS answers must differ between concurrent owners")
	}
	if len(configA.Outbound) != len(configB.Outbound) {
		t.Fatal("Two owners need identical outbound source")
	}
	for index := range configA.Outbound {
		if !proto.Equal(configA.Outbound[index], configB.Outbound[index]) {
			t.Fatal("Two owners must start with byte-equal caller outbounds")
		}
	}
	t.Log("PHASE two simultaneous Core owners: construct/start")
	ownerA := startOwner(t, configA, dnsA, "::1", port)
	ownerB := startOwner(t, configB, dnsB, "127.0.0.1", port)
	for _, item := range []struct {
		owner  *ownedCore
		marker string
	}{{ownerA, "OWNER_A"}, {ownerB, "OWNER_B"}, {ownerA, "OWNER_A"}} {
		marker(t, item.owner, "remote-marker.invalid", 80, item.marker)
	}
	t.Log("PHASE caller hosts and freedom share endpoint hostname/port: check")
	for _, item := range []struct {
		engine                 *ownedCore
		callerIP, callerMarker string
	}{{ownerA, "127.0.0.1", "CALLER_V4"}, {ownerB, "::1", "CALLER_V6"}} {
		engine := item.engine
		client := engine.core.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
		ips, _, err := client.LookupIP(endpointHost, featureDNS.IPOption{IPv4Enable: true, IPv6Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP(item.callerIP)) {
			t.Fatalf("Caller hosts lookup was replaced by a transport pin: %v %v", ips, err)
		}
		marker(t, engine, endpointHost, port, item.callerMarker)
		marker(t, engine, "alpha.invalid", port, "CALLER_V4")
		marker(t, engine, "beta.invalid", port, "CALLER_V6")
		sourceUnchanged(t, engine)
	}
	t.Log("PHASE observed per-domain TCP DNS/tag routes: check")
	for _, item := range []struct {
		server   *loopServer
		question string
	}{{alpha, "alpha.invalid. 1"}, {beta, "beta.invalid. 28"}} {
		observed, errors := item.server.observations()
		if len(errors) != 0 || len(observed) < 2 {
			t.Fatalf("Missing per-owner TCP DNS queries: observed=%v errors=%v", observed, errors)
		}
		for _, question := range observed {
			if question != item.question {
				t.Fatalf("Wrong domain/family reached tagged DNS server: %s", question)
			}
		}
	}
	t.Log("PHASE rejected candidate preflight leaves both owners alive: check")
	if _, err := internet.NewNativeDNSOwner([]internet.NativeDNSBinding{{Key: configA.Outbound[0], SourceIndex: 0, ProxyType: configA.Outbound[0].ProxySettings.Type, TransportEndpoints: true}}); err == nil {
		t.Fatal("Invalid candidate endpoint preflight was accepted")
	}
	if _, err := core.LoadConfig("json", strings.NewReader(`{"outbounds":[`)); err == nil {
		t.Fatal("Malformed candidate config was accepted")
	}
	marker(t, ownerA, "remote-marker.invalid", 80, "OWNER_A")
	marker(t, ownerB, "remote-marker.invalid", 80, "OWNER_B")
	t.Log("PHASE owner A closes while Core A is alive: stale traffic is refused")
	_ = ownerA.owner.Close()
	beforeV4, _ := v4.observations()
	beforeV6, _ := v6.observations()
	if _, err := fetchMarker(ownerA, "remote-marker.invalid", 80); err == nil {
		t.Fatal("Closed owner A still served traffic before Core A close")
	}
	afterV4, _ := v4.observations()
	afterV6, _ := v6.observations()
	if len(beforeV4) != len(afterV4) || len(beforeV6) != len(afterV6) {
		t.Fatal("Closed owner initiated new fixture traffic")
	}
	marker(t, ownerB, "remote-marker.invalid", 80, "OWNER_B")
	t.Log("PHASE Core A closes; owner B remains functional")
	if err := ownerA.close(); err != nil {
		t.Fatalf("Core A close failed: %v", err)
	}
	marker(t, ownerB, "remote-marker.invalid", 80, "OWNER_B")
	marker(t, ownerB, endpointHost, port, "CALLER_V6")
	marker(t, ownerB, "alpha.invalid", port, "CALLER_V4")
	sourceUnchanged(t, ownerB)
	t.Log("PHASE no-DNS raw factory ordering only; protected local DNS remains gated")
	minimal, absentDNS := makeConfig(t, port, nil, nil, false, "")
	minimalOwner := startOwner(t, minimal, absentDNS, "127.0.0.1", port)
	if minimalOwner.core.GetFeature(featureDNS.ClientType()) == nil {
		t.Fatal("Essential default DNS feature was not constructed")
	}
	marker(t, minimalOwner, "remote-marker.invalid", 80, "OWNER_B")
	marker(t, ownerB, "alpha.invalid", port, "CALLER_V4")
	marker(t, ownerB, endpointHost, port, "CALLER_V6")
	sourceUnchanged(t, ownerB)
	for _, server := range []*loopServer{v4, v6} {
		observed, errors := server.observations()
		if len(errors) != 0 || len(observed) == 0 {
			t.Fatalf("Unexpected loopback protocol activity: observed=%v errors=%v", observed, errors)
		}
	}
	if count := externalDNSAttempts.Load(); count != 0 {
		t.Fatalf("System resolver attempted %d DNS dials", count)
	}
	t.Log("PASS actual Core native DNS context runtime: owners, caller DNS, tags, lifetime and preflight")
}
