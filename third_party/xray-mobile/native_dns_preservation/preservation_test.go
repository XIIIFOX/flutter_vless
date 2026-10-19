package native_dns_preservation_test

// Real ordinary pinned Core consuming the production native preparer's JSON.
// CI only. Every socket is loopback; no TUN, host DNS or routes are changed.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fixture struct {
	mu      sync.Mutex
	queries []string
	errors  []error
}

func (f *fixture) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, name)
}
func (f *fixture) fail(err error) {
	if err != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.errors = append(f.errors, err)
	}
}
func (f *fixture) snapshot() ([]string, []error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]error(nil), f.errors...)
}

func listener(t *testing.T, serve func(net.Conn)) net.Listener {
	return networkListener(t, "tcp4", "127.0.0.1:0", serve)
}

func networkListener(t *testing.T, network, address string, serve func(net.Conn)) net.Listener {
	t.Helper()
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	closed := false
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			active[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(7 * time.Second):
			t.Error("owned fixture sockets did not close")
		}
	})
	return l
}

func reply(f *fixture, packet []byte, host, ip string) ([]byte, error) {
	q := new(dns.Msg)
	if err := q.Unpack(packet); err != nil {
		return nil, err
	}
	if len(q.Question) != 1 {
		return nil, errors.New("one DNS question required")
	}
	f.record(fmt.Sprintf("%s/%d", q.Question[0].Name, q.Question[0].Qtype))
	r := new(dns.Msg)
	r.SetReply(q)
	if q.Question[0].Name != host+"." || q.Question[0].Qtype != dns.TypeA {
		r.Rcode = dns.RcodeRefused
	} else {
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(ip)}}
	}
	return r.Pack()
}

func tcpResolver(t *testing.T, f *fixture, host, ip string) int {
	l := listener(t, func(c net.Conn) {
		for { // Core may reuse one upstream TCP connection.
			var size uint16
			if err := binary.Read(c, binary.BigEndian, &size); err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					f.fail(err)
				}
				return
			}
			if size == 0 || size > 4096 {
				f.fail(errors.New("unbounded DNS frame"))
				return
			}
			packet := make([]byte, size)
			if _, err := io.ReadFull(c, packet); err != nil {
				f.fail(err)
				return
			}
			answer, err := reply(f, packet, host, ip)
			if err != nil {
				f.fail(err)
				return
			}
			if err := binary.Write(c, binary.BigEndian, uint16(len(answer))); err != nil {
				f.fail(err)
				return
			}
			if _, err := c.Write(answer); err != nil {
				f.fail(err)
				return
			}
		}
	})
	return l.Addr().(*net.TCPAddr).Port
}

func udpResolver(t *testing.T, f *fixture, host, ip string) int {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 4096)
		for {
			n, peer, err := c.ReadFromUDP(packet)
			if err != nil {
				return
			}
			answer, err := reply(f, packet[:n], host, ip)
			if err != nil {
				f.fail(err)
				return
			}
			_, err = c.WriteToUDP(answer, peer)
			f.fail(err)
		}
	}()
	t.Cleanup(func() {
		_ = c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP fixture not closed")
		}
	})
	return c.LocalAddr().(*net.UDPAddr).Port
}

func h2cResolver(t *testing.T, f *fixture) int {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.Method != "POST" || r.URL.Path != "/dns-query" || !strings.HasPrefix(r.Host, "resolver.invalid:") {
			f.fail(errors.New("DoH host/path/method changed"))
			w.WriteHeader(400)
			return
		}
		packet, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(packet) > 4096 {
			f.fail(errors.New("unbounded DoH body"))
			w.WriteHeader(400)
			return
		}
		answer, err := reply(f, packet, "gamma.invalid", "192.0.2.13")
		if err != nil {
			f.fail(err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, err = w.Write(answer)
		f.fail(err)
	})
	l := listener(t, func(c net.Conn) {
		server := new(http2.Server)
		server.ServeConn(c, &http2.ServeConnOpts{Handler: handler})
	})
	return l.Addr().(*net.TCPAddr).Port
}

func socksMarker(t *testing.T, f *fixture) int {
	l := listener(t, func(c net.Conn) {
		reader := bufio.NewReader(c)
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			f.fail(err)
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(reader, methods); err != nil {
			f.fail(err)
			return
		}
		if header[0] != 5 || !bytes.Contains(methods, []byte{0}) {
			f.fail(errors.New("bad upstream SOCKS greeting"))
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var connect [5]byte
		if _, err := io.ReadFull(reader, connect[:]); err != nil {
			f.fail(err)
			return
		}
		if !bytes.Equal(connect[:4], []byte{5, 1, 0, 3}) {
			f.fail(errors.New("logical proxy target was resolved or rewritten"))
			return
		}
		host := make([]byte, int(connect[4]))
		if _, err := io.ReadFull(reader, host); err != nil {
			f.fail(err)
			return
		}
		var port uint16
		if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
			f.fail(err)
			return
		}
		if string(host) != "remote-marker.invalid" || port != 80 {
			f.fail(errors.New("wrong proxy target"))
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		r, err := http.ReadRequest(reader)
		if err != nil {
			f.fail(err)
			return
		}
		defer r.Body.Close()
		if r.Host != "remote-marker.invalid" {
			f.fail(errors.New("HTTP Host changed"))
			return
		}
		f.record("HTTP " + r.Host)
		marker := "PINNED_ENDPOINT_OK"
		_, err = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(marker), marker)
		f.fail(err)
	})
	return l.Addr().(*net.TCPAddr).Port
}

func loopbackInterface(t *testing.T) string {
	t.Helper()
	entries, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range entries {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	t.Fatal("loopback interface required")
	return ""
}

func prepare(t *testing.T, source map[string]any) ([]byte, int) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.json"), filepath.Join(dir, "effective.json")
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	preparer := os.Getenv("NATIVE_DNS_PREPARER")
	if preparer == "" {
		t.Fatal("production native preparer exporter required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, preparer, "--prepare-dns-fixture", input, output, loopbackInterface(t), "endpoint.invalid", "127.0.0.1")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native prepare failed: %v: %s", err, combined)
	}
	prepared, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	wantDNS, _ := json.Marshal(source["dns"])
	gotDNS, _ := json.Marshal(effective["dns"])
	if !bytes.Equal(wantDNS, gotDNS) {
		t.Fatal("production preparation replaced caller DNS")
	}
	wantOut, _ := json.Marshal(nativeExpectedSettings(source["outbounds"].([]any)[0].(map[string]any)))
	gotOut, _ := json.Marshal(effective["outbounds"].([]any)[0].(map[string]any)["settings"])
	if !bytes.Equal(wantOut, gotOut) {
		t.Fatal("logical proxy endpoint changed")
	}
	inbounds := effective["inbounds"].([]any)
	managed := inbounds[0].(map[string]any)
	t.Logf("NATIVE_DNS_EFFECTIVE_SHA256=%x", sha256.Sum256(prepared))
	return prepared, int(managed["port"].(float64))
}

func auth(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	failed := true
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	_, err = c.Write([]byte{5, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(c, response); err != nil || !bytes.Equal(response, []byte{5, 2}) {
		t.Fatal("SOCKS password method required", err)
	}
	user, password := "session-user", "session-password"
	packet := append([]byte{1, byte(len(user))}, user...)
	packet = append(packet, byte(len(password)))
	packet = append(packet, password...)
	if _, err = c.Write(packet); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, response); err != nil || !bytes.Equal(response, []byte{1, 0}) {
		t.Fatal("native auth failed", err)
	}
	failed = false
	return c
}

func connect(t *testing.T, port int, command byte, target netip.AddrPort, domain string) (net.Conn, netip.AddrPort) {
	t.Helper()
	c := auth(t, port)
	packet := []byte{5, command, 0}
	if domain != "" {
		packet = append(packet, 3, byte(len(domain)))
		packet = append(packet, domain...)
	} else {
		if target.Addr().Is4() {
			packet = append(packet, 1)
			ip := target.Addr().As4()
			packet = append(packet, ip[:]...)
		} else {
			packet = append(packet, 4)
			ip := target.Addr().As16()
			packet = append(packet, ip[:]...)
		}
	}
	packet = binary.BigEndian.AppendUint16(packet, target.Port())
	if _, err := c.Write(packet); err != nil {
		c.Close()
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(c, response); err != nil || !bytes.Equal(response[:4], []byte{5, 0, 0, 1}) {
		c.Close()
		t.Fatal("SOCKS command failed", err)
	}
	return c, netip.AddrPortFrom(netip.AddrFrom4([4]byte{response[4], response[5], response[6], response[7]}), binary.BigEndian.Uint16(response[8:]))
}

func query(t *testing.T, port int, udp bool, name string, qtype uint16) *dns.Msg {
	t.Helper()
	question := new(dns.Msg)
	question.SetQuestion(name+".", qtype)
	question.Id = 0x7139
	packet, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var response []byte
	virtual := netip.MustParseAddrPort("198.18.0.2:53")
	if udp {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		control, relay := connect(t, port, 3, c.LocalAddr().(*net.UDPAddr).AddrPort(), "")
		defer control.Close()
		packet = append([]byte{0, 0, 0, 1, 198, 18, 0, 2, 0, 53}, packet...)
		if _, err := c.WriteToUDPAddrPort(packet, relay); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		buffer := make([]byte, 4096)
		n, peer, err := c.ReadFromUDPAddrPort(buffer)
		if err != nil || n < 22 || peer != relay || !bytes.Equal(buffer[:10], []byte{0, 0, 0, 1, 198, 18, 0, 2, 0, 53}) {
			t.Fatal("exact VIP UDP DNS response missing", err)
		}
		response = buffer[10:n]
	} else {
		c, _ := connect(t, port, 1, virtual, "")
		defer c.Close()
		if err := binary.Write(c, binary.BigEndian, uint16(len(packet))); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(packet); err != nil {
			t.Fatal(err)
		}
		var size uint16
		if err := binary.Read(c, binary.BigEndian, &size); err != nil || size == 0 || size > 4096 {
			t.Fatal("TCP DNS response missing", err)
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(c, response); err != nil {
			t.Fatal(err)
		}
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(response); err != nil {
		t.Fatal(err)
	}
	if answer.Id != question.Id || !reflect.DeepEqual(answer.Question, question.Question) {
		t.Fatal("question identity changed")
	}
	return answer
}

func TestNativeDNSPreservation(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("actual Core execution is CI-only")
	}
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production C++ exporter required")
	}
	t.Run("WindowsPreparer", testNativeDNSPreservation)
	t.Run("WindowsIPv6Payload", testNativeIPv6Payload)
	t.Run("WindowsHTTPSDoH", testNativeHTTPSDoH)
	t.Run("WindowsDirectOnly", testNativeDirectOnly)
	t.Run("WindowsPrefixBalancer", func(t *testing.T) { runNativeDirectOnly(t, selectorTrafficProfile(t)) })
	t.Run("WindowsNullDirectTag", testNativeNullDirectTag)
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		t.Run("ApplePreparer", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeDNSPreservation(t) })
		t.Run("AppleIPv6Payload", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeIPv6Payload(t) })
		t.Run("AppleHTTPSDoH", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeHTTPSDoH(t) })
		t.Run("AppleDirectOnly", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeDirectOnly(t) })
		t.Run("ApplePrefixBalancer", func(t *testing.T) {
			t.Setenv("NATIVE_DNS_PREPARER", apple)
			runNativeDirectOnly(t, selectorTrafficProfile(t))
		})
		t.Run("AppleNullDirectTag", func(t *testing.T) {
			t.Setenv("NATIVE_DNS_PREPARER", apple)
			testNativeNullDirectTag(t)
		})
	}
}

func testNativeDNSPreservation(t *testing.T) {
	var systemAttempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden OS resolver")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if systemAttempts.Load() != 0 {
			t.Error("ordinary Core attempted OS resolver")
		}
	})
	alpha, beta, gamma, origin := new(fixture), new(fixture), new(fixture), new(fixture)
	completed := false
	// Register before every server and engine cleanup: observations must include
	// all owned callbacks, including any final retry during shutdown.
	t.Cleanup(func() {
		if !completed {
			return
		}
		for name, f := range map[string]*fixture{"alpha": alpha, "beta": beta, "gamma": gamma} {
			queries, failures := f.snapshot()
			if len(queries) != 2 || len(failures) != 0 {
				t.Errorf("%s: expected 2 source-selected A queries, got %v errors %v", name, queries, failures)
			}
		}
		queries, failures := origin.snapshot()
		if !reflect.DeepEqual(queries, []string{"HTTP remote-marker.invalid", "HTTP remote-marker.invalid"}) || len(failures) != 0 {
			t.Error("physical endpoint/Host proof failed", queries, failures)
		}
	})
	alphaPort := tcpResolver(t, alpha, "alpha.invalid", "192.0.2.11")
	betaPort := udpResolver(t, beta, "beta.invalid", "192.0.2.12")
	gammaPort := h2cResolver(t, gamma)
	proxyPort := socksMarker(t, origin)
	unixDirectory, err := os.MkdirTemp("", "fv-listen-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(unixDirectory); err != nil {
			t.Error(err)
		}
	})
	unixAddress := filepath.Join(unixDirectory, "in.sock")
	t.Setenv("FLUTTER_VLESS_FIXTURE_LISTEN", unixAddress)
	// Keep the caller API separate from the adapter. Reserve its port through
	// preparation so the native allocator must account for an existing service.
	apiReservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiReservation.Close() })
	apiAddress := apiReservation.Addr().String()
	source := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"tag": "caller-unix", "protocol": "http",
			"listen": "env:FLUTTER_VLESS_FIXTURE_LISTEN", "port": "0-65535",
			"settings": map[string]any{}}},
		"api": map[string]any{"tag": "caller-api", "listen": apiAddress,
			"services": []string{"StatsService", "HandlerService", "LoggerService"}},
		"stats": map[string]any{},
		"policy": map[string]any{"system": map[string]any{
			"statsInboundUplink": false, "statsInboundDownlink": false,
			"statsOutboundUplink": false, "statsOutboundDownlink": false}},
		"outbounds": []any{
			map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "endpoint.invalid", "port": proxyPort}}}},
			map[string]any{"tag": "dns-direct", "protocol": "direct", "settings": map[string]any{"domainStrategy": "AsIs", "finalRules": []any{map[string]any{"action": "allow"}}}},
			map[string]any{"tag": "block", "protocol": "block"},
			map[string]any{"tag": "caller-loop", "protocol": "loopback", "settings": map[string]any{"inboundTag": "caller-loop-input"}},
			map[string]any{"tag": "caller-dns-relay", "protocol": "dns", "settings": map[string]any{"rewriteAddress": "127.0.0.1", "rewritePort": alphaPort, "rewriteNetwork": "tcp"}},
		},
		"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.2", "resolver.invalid": []string{"127.0.0.1"}, "static.invalid": "192.0.2.14"}, "tag": "flutter-vless-tun", "queryStrategy": "UseIPv4", "disableCache": true, "disableFallbackIfMatch": true, "servers": []any{
			map[string]any{"address": fmt.Sprintf("tcp://127.0.0.1:%d", alphaPort), "domains": []string{"full:alpha.invalid"}, "tag": "flutter-vless-bootstrap-input", "skipFallback": true, "queryStrategy": "UseIPv4"},
			map[string]any{"address": "127.0.0.1", "port": betaPort, "domains": []string{"full:beta.invalid"}, "tag": "beta-client", "skipFallback": true, "queryStrategy": "UseIPv4"},
			map[string]any{"address": fmt.Sprintf("h2c://resolver.invalid:%d/dns-query", gammaPort), "domains": []string{"full:gamma.invalid"}, "tag": "gamma-client", "skipFallback": true, "queryStrategy": "UseIPv4"},
		}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"caller-loop-input"}, "outboundTag": "proxy"},
			map[string]any{"type": "field", "domain": []string{"full:remote-marker.invalid"}, "outboundTag": "caller-loop"},
			map[string]any{"type": "field", "inboundTag": []string{"flutter-vless-bootstrap-input"}, "outboundTag": "caller-dns-relay"},
			map[string]any{"type": "field", "inboundTag": []string{"beta-client", "gamma-client"}, "outboundTag": "dns-direct"},
			map[string]any{"type": "field", "port": fmt.Sprintf("%d,%d,%d", alphaPort, betaPort, gammaPort), "outboundTag": "block"},
		}},
	}
	prepared, port := prepare(t, source)
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	assertCallerServiceRoots(t, source, effective)
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := apiReservation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	api, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	queryCallerCounters := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		statistics, err := statscommand.NewStatsServiceClient(api).QueryStats(ctx, &statscommand.QueryStatsRequest{})
		if err != nil {
			t.Fatal("caller StatsService is unavailable after native preparation", err)
		}
		if len(statistics.Stat) != 0 {
			t.Fatal("caller disabled counters were enabled by adaptation")
		}
	}
	// A successful RPC also establishes that Commander's asynchronous Serve
	// goroutine entered before a later fixture failure can close the engine.
	queryCallerCounters()
	unixClient, err := net.DialTimeout("unix", unixAddress, time.Second)
	if err != nil {
		t.Fatal("caller environment Unix listener did not bind", err)
	}
	defer unixClient.Close()
	_ = unixClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(unixClient, "GET http://remote-marker.invalid/proof HTTP/1.1\r\nHost: remote-marker.invalid\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	unixResponse, err := http.ReadResponse(bufio.NewReader(unixClient), nil)
	if err != nil {
		t.Fatal("caller environment Unix HTTP listener is unavailable", err)
	}
	unixBody, err := io.ReadAll(io.LimitReader(unixResponse.Body, 1024))
	_ = unixResponse.Body.Close()
	if err != nil || string(unixBody) != "PINNED_ENDPOINT_OK" {
		t.Fatal("caller environment Unix HTTP listener did not carry routed bytes", err)
	}
	if err := unixClient.Close(); err != nil {
		t.Fatal(err)
	}
	for _, udp := range []bool{false, true} {
		for name, want := range map[string]string{"alpha.invalid": "192.0.2.11", "beta.invalid": "192.0.2.12", "gamma.invalid": "192.0.2.13", "static.invalid": "192.0.2.14"} {
			answer := query(t, port, udp, name, dns.TypeA)
			if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatalf("%s UDP=%v: no A response: %s", name, udp, answer)
			}
			ip, ok := answer.Answer[0].(*dns.A)
			if !ok || ip.A.String() != want {
				t.Fatalf("%s DNS policy result changed: %s", name, answer)
			}
		}
		for _, kind := range []uint16{dns.TypeAAAA, dns.TypeMX} {
			answer := query(t, port, udp, "alpha.invalid", kind)
			want := dns.RcodeSuccess
			if kind == dns.TypeMX {
				want = dns.RcodeRefused
			}
			if answer.Rcode != want || len(answer.Answer) != 0 {
				t.Fatalf("address-only bridge response mismatch: %s", answer)
			}
		}
	}
	httpConn, _ := connect(t, port, 1, netip.MustParseAddrPort("0.0.0.0:80"), "remote-marker.invalid")
	defer httpConn.Close()
	_, err = io.WriteString(httpConn, "GET /proof HTTP/1.1\r\nHost: remote-marker.invalid\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(httpConn), nil)
	if err != nil {
		t.Fatal("pinned endpoint inaccessible despite unchanged root hosts", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	if err != nil || string(body) != "PINNED_ENDPOINT_OK" {
		t.Fatal("proxy HTTP marker missing", err)
	}
	queryCallerCounters()
	completed = true
	t.Log("PASS actual native DNS: preserved root hosts/servers/tags/per-domain policy, TCP+UDP VIP, numeric TCP+UDP upstream, named h2c static host, AAAA NODATA, MX REFUSED, isolated endpoint pin and HTTP bytes; caller API/StatsService works with disabled counters; environment Unix HTTP listener carries routed bytes; no OS resolver")
}
