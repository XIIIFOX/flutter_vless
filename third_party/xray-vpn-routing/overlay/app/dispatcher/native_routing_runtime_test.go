package dispatcher_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const nativeRuntimeUser = "owned-routing-user"
const nativeRuntimePassword = "owned-routing-password"

// These are real ordinary-Core listeners and byte paths, never a platform VPN
// qualification. Fail before creating any socket or Core outside remote CI.
func TestNativeVPNRoutingRuntime(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("native VPN routing runtime is CI-only")
	}
	f := newNativeRuntime(t)
	t.Run("authenticated-tcp-udp-alias-default-and-imported-isolation", func(t *testing.T) {
		f.tcp(t, f.privatePort, "alias.invalid", 443, "alias", "alias-tcp")
		f.tcp(t, f.privatePort, "miss.invalid", 443, "default", "default-tcp")
		u := f.udp(t)
		defer u.close()
		// Ordinary Core keeps one routed ray per SOCKS association. Preserve
		// that contract, including repeated same-target UDP metadata copies.
		u.marker(t, "alias.invalid", 443, "alias", "alias-udp")
		u.marker(t, "alias.invalid", 443, "alias", "alias-udp-repeat")
		other := f.udp(t)
		defer other.close()
		other.marker(t, "miss.invalid", 443, "default", "default-udp")
		f.blocked(t, f.importedPort, "alias.invalid")
		f.blocked(t, f.importedPort, "miss.invalid")
		f.tcp(t, f.importedPort, "imported.invalid", 443, "imported", "imported-before")
	})
	t.Run("real-ipifnonmatch-second-pass-and-private-guards", func(t *testing.T) {
		f.tcp(t, f.privatePort, "ip-route.invalid", 443, "ip", "ip-second-pass")
		f.dnsTCP(t, false)
		u := f.udp(t)
		defer u.close()
		question := nativeRuntimeDNSQuestion(t)
		nativeRuntimeDNSAnswer(t, u.exchange(t, "198.18.0.2", 53, question))
		f.tcp(t, f.privatePort, "127.0.0.1", 13891, "probe", "private-probe")
		// This separate trusted Core.Dial control deliberately has no private
		// SOCKS grant. It proves a native literal guard precedes a forced detour;
		// authenticated TCP/UDP DNS above proves the actual private input path.
		f.dnsTCP(t, true)
	})
	t.Run("actual-live-router-add-remove-and-replacement", func(t *testing.T) {
		f.tcp(t, f.privatePort, "dynamic.invalid", 443, "default", "dynamic-before")
		f.replaceRules(t, []json.RawMessage{json.RawMessage(`{"type":"field","ruleTag":"live-added","inboundTag":["caller-input"],"domain":["full:dynamic.invalid"],"outboundTag":"dynamic"}`)}, true)
		f.tcp(t, f.privatePort, "dynamic.invalid", 443, "dynamic", "dynamic-added")
		if err := f.caller.RemoveRule("live-added"); err != nil {
			t.Fatal(err)
		}
		f.tcp(t, f.privatePort, "dynamic.invalid", 443, "default", "dynamic-removed")
		// A full RoutingAPI-style replacement remains live. Private DNS/probe
		// guards are outside that caller router and survive the replacement.
		f.replaceRules(t, []json.RawMessage{json.RawMessage(`{"type":"field","inboundTag":["caller-input"],"network":"tcp,udp","outboundTag":"dynamic"}`)}, false)
		f.tcp(t, f.privatePort, "alias.invalid", 443, "dynamic", "dynamic-replacement")
		f.dnsTCP(t, false)
		f.tcp(t, f.privatePort, "127.0.0.1", 13891, "probe", "probe-after-replacement")
		f.replaceRules(t, f.originalRules, false)
	})
	t.Run("owner-close-revokes-private-only", func(t *testing.T) {
		private, _ := f.connect(t, f.privatePort, 1, "miss.invalid", 443)
		defer private.Close()
		f.exchangeMarker(t, private, "default", "private-held")
		imported, _ := f.connect(t, f.importedPort, 1, "imported.invalid", 443)
		defer imported.Close()
		f.exchangeMarker(t, imported, "imported", "imported-held-before")
		until := time.Now().Add(2 * time.Second)
		if err := f.owner.Close(); err != nil {
			t.Fatal(err)
		}
		nativeRuntimeClosed(t, private, until)
		// Revocation affects only its exact constructed input; imported live
		// control and a fresh imported flow still use unchanged caller routes.
		f.exchangeMarker(t, imported, "imported", "imported-held-after")
		f.tcp(t, f.importedPort, "imported.invalid", 443, "imported", "imported-after")
		late, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", f.privatePort), time.Until(until))
		if err == nil {
			defer late.Close()
			nativeRuntimeClosed(t, late, until)
		} else if !errors.Is(err, syscall.ECONNREFUSED) && !nativeRuntimeClosedError(err, runtime.GOOS) {
			t.Fatal("late private control was not explicitly refused", err)
		}
		if !time.Now().Before(until) {
			t.Fatal("private owner revocation exceeded its shared deadline")
		}
	})
}

type nativeRuntimeOrigin struct {
	name     string
	tcp      net.Listener
	udp      *net.UDPConn
	mu       sync.Mutex
	closed   bool
	active   map[net.Conn]bool
	seen     map[string]int
	failures []string
	wg       sync.WaitGroup
}

func newNativeRuntimeOrigin(t *testing.T, name, nonce string) *nativeRuntimeOrigin {
	t.Helper()
	l, u, err := nativeRuntimeReserveOriginPair(func() (net.Listener, int, error) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		return listener, listener.Addr().(*net.TCPAddr).Port, nil
	}, func(port int) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	}, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	o := &nativeRuntimeOrigin{name: name, tcp: l, udp: u, active: map[net.Conn]bool{}, seen: map[string]int{}}
	response := func(payload []byte) ([]byte, bool) {
		if len(payload) == 0 || len(payload) > 256 || !bytes.HasPrefix(payload, []byte(nonce+"/")) {
			o.mu.Lock()
			o.failures = append(o.failures, "unexpected marker payload")
			o.mu.Unlock()
			return nil, false
		}
		o.mu.Lock()
		o.seen[string(payload)]++
		o.mu.Unlock()
		return append([]byte(name+"|"), payload...), true
	}
	o.wg.Add(2)
	go func() {
		defer o.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			o.mu.Lock()
			if o.closed {
				o.mu.Unlock()
				_ = c.Close()
				return
			}
			o.active[c] = true
			o.wg.Add(1)
			o.mu.Unlock()
			go func() {
				defer o.wg.Done()
				defer c.Close()
				defer func() { o.mu.Lock(); delete(o.active, c); o.mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					payload, err := nativeRuntimeReadFrame(c)
					if err != nil {
						return
					}
					answer, ok := response(payload)
					if !ok {
						return
					}
					if err := nativeRuntimeWriteFrame(c, answer); err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		defer o.wg.Done()
		packet := make([]byte, 512)
		for {
			n, peer, err := u.ReadFromUDP(packet)
			if err != nil {
				return
			}
			answer, ok := response(packet[:n])
			if !ok {
				continue
			}
			if _, err = u.WriteToUDP(answer, peer); err != nil {
				return
			}
		}
	}()
	return o
}

func (o *nativeRuntimeOrigin) close(until time.Time) error {
	o.mu.Lock()
	o.closed = true
	active := make([]net.Conn, 0, len(o.active))
	for c := range o.active {
		active = append(active, c)
	}
	o.mu.Unlock()
	_ = o.tcp.Close()
	_ = o.udp.Close()
	for _, c := range active {
		_ = c.Close()
	}
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(time.Until(until)):
		return errors.New("marker workers did not drain")
	}
}

type nativeRuntimeFixture struct {
	t                         *testing.T
	nonce                     string
	privatePort, importedPort int
	origins                   map[string]*nativeRuntimeOrigin
	expected                  map[string]map[string]int
	owner                     *routing.NativeRoutingOwner
	engine                    *core.Instance
	caller                    routing.Router
	originalRules             []json.RawMessage
}

func newNativeRuntime(t *testing.T) *nativeRuntimeFixture {
	t.Helper()
	f := &nativeRuntimeFixture{t: t, origins: map[string]*nativeRuntimeOrigin{}, expected: map[string]map[string]int{}}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	f.nonce = hex.EncodeToString(nonce[:])
	var resolverAttempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		resolverAttempts.Add(1)
		return nil, errors.New("runtime fixture forbids OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	// Every cleanup is attempted under one deadline, including setup failures.
	t.Cleanup(func() {
		until := time.Now().Add(3 * time.Second)
		if f.owner != nil {
			if err := f.owner.Close(); err != nil {
				t.Error("owner cleanup", err)
			}
		}
		if f.engine != nil {
			done := make(chan error, 1)
			go func() { done <- f.engine.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Error("Core cleanup", err)
				}
			case <-time.After(time.Until(until)):
				t.Error("Core cleanup deadline")
			}
		}
		for _, o := range f.origins {
			if err := o.close(until); err != nil {
				t.Error(err)
			}
		}
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if resolverAttempts.Load() != 0 {
			t.Error("runtime attempted OS resolver")
		}
		for name, o := range f.origins {
			o.mu.Lock()
			seen := make(map[string]int, len(o.seen))
			for key, value := range o.seen {
				seen[key] = value
			}
			failures := append([]string(nil), o.failures...)
			o.mu.Unlock()
			if !reflect.DeepEqual(seen, f.expected[name]) || len(failures) != 0 {
				t.Errorf("marker %s mismatch: actual-count=%d expected-count=%d failures=%d", name, len(seen), len(f.expected[name]), len(failures))
			}
		}
		t.Log("native routing cleanup: owner revoked, Core/listeners/marker workers drained; OS resolver attempts=0")
	})
	for _, name := range []string{"alias", "default", "ip", "dynamic", "imported", "probe"} {
		f.origins[name] = newNativeRuntimeOrigin(t, name, f.nonce)
		f.expected[name] = map[string]int{}
	}
	reserve := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	privateReservation, importedReservation := reserve(), reserve()
	f.privatePort = privateReservation.Addr().(*net.TCPAddr).Port
	f.importedPort = importedReservation.Addr().(*net.TCPAddr).Port
	f.originalRules = []json.RawMessage{
		json.RawMessage(`{"type":"field","inboundTag":["caller-input"],"domain":["full:alias.invalid"],"outboundTag":"alias"}`),
		json.RawMessage(`{"type":"field","inboundTag":["caller-input"],"ip":["192.0.2.42/32"],"outboundTag":"ip"}`),
		json.RawMessage(`{"type":"field","inboundTag":["caller-input"],"ip":["198.18.0.2/32"],"port":"53","outboundTag":"blocked"}`),
		json.RawMessage(`{"type":"field","inboundTag":["caller-input"],"ip":["127.0.0.1/32"],"port":"13891","outboundTag":"blocked"}`),
		json.RawMessage(`{"type":"field","domain":["full:imported.invalid"],"outboundTag":"imported"}`),
	}
	outbounds := []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}}
	for _, name := range []string{"alias", "default", "ip", "dynamic", "imported", "probe"} {
		outbounds = append(outbounds, map[string]any{"tag": name, "protocol": "freedom", "settings": map[string]any{"redirect": f.origins[name].tcp.Addr().String()}})
	}
	outbounds = append(outbounds, map[string]any{"tag": "private-dns", "protocol": "dns", "settings": map[string]any{"rules": []any{map[string]any{"action": "hijack", "qType": "1"}, map[string]any{"action": "return", "rCode": 5}}}})
	source := map[string]any{"log": map[string]any{"loglevel": "none"}, "dns": map[string]any{"queryStrategy": "UseIPv4", "hosts": map[string]any{"alias.invalid": "192.0.2.101", "miss.invalid": "192.0.2.102", "dynamic.invalid": "192.0.2.103", "imported.invalid": "192.0.2.104", "ip-route.invalid": "192.0.2.42", "guard.invalid": "192.0.2.66"}},
		"inbounds":  []any{map[string]any{"tag": "managed-input", "listen": "127.0.0.1", "port": f.privatePort, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": nativeRuntimeUser, "pass": nativeRuntimePassword}}, "udp": true, "ip": "127.0.0.1"}}, map[string]any{"tag": "imported-input", "listen": "127.0.0.1", "port": f.importedPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": outbounds, "routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": f.originalRules}}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := confserial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := configuration.Build()
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: compiled.Inbound[0], ManagedTag: "managed-input", AuthUser: nativeRuntimeUser, AliasEnabled: true, InboundAlias: "caller-input", DefaultOutboundTag: "default", MaxFlows: 0})
	if err != nil {
		t.Fatal(err)
	}
	var guards conf.RouterConfig
	if err = json.Unmarshal([]byte(`{"rules":[{"type":"field","inboundTag":["managed-input"],"ip":["198.18.0.2/32"],"port":"53","network":"tcp,udp","outboundTag":"private-dns"},{"type":"field","inboundTag":["managed-input"],"ip":["127.0.0.1/32"],"port":"13891","network":"tcp","outboundTag":"probe"}]}`), &guards); err != nil {
		t.Fatal(err)
	}
	guardConfig, err := guards.Build()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := dispatcher.ContextWithNativeVPNRouting(context.Background(), f.owner, guardConfig.Rule)
	if err != nil {
		t.Fatal(err)
	}
	f.engine, err = core.NewWithContext(plan, compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.owner.Seal(f.engine); err != nil {
		t.Fatal(err)
	}
	f.caller = f.engine.GetFeature(routing.RouterType()).(routing.Router)
	_ = privateReservation.Close()
	_ = importedReservation.Close()
	if err = f.engine.Start(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *nativeRuntimeFixture) replaceRules(t *testing.T, rules []json.RawMessage, appendRules bool) {
	t.Helper()
	config := &conf.RouterConfig{RuleList: rules}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.caller.AddRule(serial.ToTypedMessage(built), appendRules); err != nil {
		t.Fatal(err)
	}
}

func nativeRuntimeAddress(host string, port int) []byte {
	var b []byte
	if ip := net.ParseIP(host).To4(); ip != nil {
		b = append([]byte{1}, ip...)
	} else {
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func (f *nativeRuntimeFixture) connect(t *testing.T, port int, command byte, host string, targetPort int) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	failed := true
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	method := byte(0)
	if port == f.privatePort {
		method = 2
	}
	if _, err = c.Write([]byte{5, 1, method}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, method} {
		t.Fatal("SOCKS method mismatch", err)
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(nativeRuntimeUser))}, nativeRuntimeUser...)
		auth = append(auth, byte(len(nativeRuntimePassword)))
		auth = append(auth, nativeRuntimePassword...)
		if _, err = c.Write(auth); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{1, 0} {
			t.Fatal("SOCKS authentication mismatch", err)
		}
	}
	if _, err = c.Write(append([]byte{5, command, 0}, nativeRuntimeAddress(host, targetPort)...)); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || !bytes.Equal(response[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("SOCKS command mismatch", err)
	}
	failed = false
	return c, &net.UDPAddr{IP: net.IP(response[4:8]), Port: int(binary.BigEndian.Uint16(response[8:]))}
}

func nativeRuntimeWriteFrame(w io.Writer, payload []byte) error {
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...))
	return err
}
func nativeRuntimeReadFrame(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > 512 {
		return nil, errors.New("invalid marker frame size")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func (f *nativeRuntimeFixture) exchangeMarker(t *testing.T, c net.Conn, marker, label string) {
	t.Helper()
	payload := []byte(f.nonce + "/" + label)
	if err := nativeRuntimeWriteFrame(c, payload); err != nil {
		t.Fatal(err)
	}
	answer, err := nativeRuntimeReadFrame(c)
	if err != nil || !bytes.Equal(answer, append([]byte(marker+"|"), payload...)) {
		t.Fatal("TCP marker bytes mismatch", err)
	}
	f.expected[marker][string(payload)]++
}
func (f *nativeRuntimeFixture) tcp(t *testing.T, port int, host string, targetPort int, marker, label string) {
	t.Helper()
	c, _ := f.connect(t, port, 1, host, targetPort)
	defer c.Close()
	f.exchangeMarker(t, c, marker, label)
}

// Winsock returns WSAECONNRESET (10054), whereas Go's portable ECONNRESET is
// a distinct application errno on Windows. Match the typed error chain only;
// neither timeout nor an error message alone establishes an explicit closure.
func nativeRuntimeReset(err error, goos string) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		goos == "windows" && errors.Is(err, syscall.Errno(10054))
}

// A Windows local abort is also an explicit closure, but is not a reset.
// Keep this predicate limited to typed closure errors, never timeout or text.
func nativeRuntimeClosedError(err error, goos string) bool {
	var failure net.Error
	if errors.As(err, &failure) && failure.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) ||
		nativeRuntimeReset(err, goos) ||
		goos == "windows" && errors.Is(err, syscall.Errno(10053))
}

func TestNativeVPNRoutingClosedError(t *testing.T) {
	wrapped := func(err error) error {
		return &net.OpError{Op: "read", Net: "tcp4", Err: &os.SyscallError{Syscall: "wsarecv", Err: err}}
	}
	for _, tc := range []struct {
		name   string
		err    error
		goos   string
		closed bool
	}{
		{"windows-wrapped-abort", wrapped(syscall.Errno(10053)), "windows", true},
		{"windows-abort-not-other-os", wrapped(syscall.Errno(10053)), "linux", false},
		{"windows-timeout-not-closure", wrapped(syscall.Errno(10060)), "windows", false},
		{"deadline-not-closure", wrapped(os.ErrDeadlineExceeded), "windows", false},
		{"unknown-error", wrapped(syscall.EACCES), "windows", false},
		{"nil-is-not-closure", nil, "windows", false},
		{"message-is-not-proof", errors.New("wsarecv: An established connection was aborted by the software in your host machine."), "windows", false},
		{"wrapped-eof", wrapped(io.EOF), "windows", true},
		{"wrapped-broken-pipe", wrapped(syscall.EPIPE), runtime.GOOS, true},
		{"windows-wrapped-reset", wrapped(syscall.Errno(10054)), "windows", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeRuntimeClosedError(tc.err, tc.goos); got != tc.closed {
				t.Fatalf("typed closure classification=%t, expected=%t", got, tc.closed)
			}
		})
	}
}

func TestNativeVPNRoutingClosureErrors(t *testing.T) {
	wrapped := func(err error) error {
		return &net.OpError{Op: "read", Net: "tcp4", Err: &os.SyscallError{Syscall: "wsarecv", Err: err}}
	}
	for _, tc := range []struct {
		name  string
		err   error
		goos  string
		reset bool
	}{
		{"portable-reset", wrapped(syscall.ECONNRESET), runtime.GOOS, true},
		{"windows-wrapped-reset", wrapped(syscall.Errno(10054)), "windows", true},
		{"windows-reset-not-other-os", wrapped(syscall.Errno(10054)), "linux", false},
		{"windows-abort-not-reset", wrapped(syscall.Errno(10053)), "windows", false},
		{"timeout-is-not-reset", wrapped(os.ErrDeadlineExceeded), "windows", false},
		{"eof-is-separately-checked", wrapped(io.EOF), "windows", false},
		{"unknown-error", wrapped(syscall.EACCES), "windows", false},
		{"message-is-not-proof", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), "windows", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeRuntimeReset(tc.err, tc.goos); got != tc.reset {
				t.Fatalf("typed reset classification=%t, expected=%t", got, tc.reset)
			}
		})
	}
}

func nativeRuntimeClosed(t *testing.T, c net.Conn, until time.Time) {
	t.Helper()
	_ = c.SetReadDeadline(until)
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil {
		t.Fatal("expected explicit zero-byte connection closure")
	}
	if failure, ok := err.(net.Error); ok && failure.Timeout() {
		t.Fatal("timeout is not connection closure")
	}
	if !nativeRuntimeClosedError(err, runtime.GOOS) {
		t.Fatal("unexpected connection failure", err)
	}
}
func (f *nativeRuntimeFixture) blocked(t *testing.T, port int, host string) {
	t.Helper()
	c, _ := f.connect(t, port, 1, host, 443)
	defer c.Close()
	if err := nativeRuntimeWriteFrame(c, []byte(f.nonce+"/blocked")); err != nil && !nativeRuntimeClosedError(err, runtime.GOOS) {
		t.Fatal(err)
	}
	nativeRuntimeClosed(t, c, time.Now().Add(2*time.Second))
}

type nativeRuntimeUDP struct {
	fixture *nativeRuntimeFixture
	control net.Conn
	socket  *net.UDPConn
	relay   *net.UDPAddr
}

func (f *nativeRuntimeFixture) udp(t *testing.T) *nativeRuntimeUDP {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	failed := true
	defer func() {
		if failed {
			_ = u.Close()
		}
	}()
	c, relay := f.connect(t, f.privatePort, 3, "127.0.0.1", u.LocalAddr().(*net.UDPAddr).Port)
	failed = false
	return &nativeRuntimeUDP{f, c, u, relay}
}
func (u *nativeRuntimeUDP) close() { _ = u.socket.Close(); _ = u.control.Close() }
func (u *nativeRuntimeUDP) exchange(t *testing.T, host string, port int, payload []byte) []byte {
	t.Helper()
	_ = u.socket.SetDeadline(time.Now().Add(3 * time.Second))
	packet := append(append([]byte{0, 0, 0}, nativeRuntimeAddress(host, port)...), payload...)
	if _, err := u.socket.WriteToUDP(packet, u.relay); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1024)
	n, peer, err := u.socket.ReadFromUDP(b)
	if err != nil || peer == nil || !peer.IP.Equal(u.relay.IP) || peer.Port != u.relay.Port {
		t.Fatal("UDP relay response mismatch", err)
	}
	b = b[:n]
	if len(b) < 4 || !bytes.Equal(b[:3], []byte{0, 0, 0}) {
		t.Fatal("invalid SOCKS UDP response")
	}
	size := 0
	switch b[3] {
	case 1:
		size = 10
	case 4:
		size = 22
	case 3:
		if len(b) < 5 {
			t.Fatal("short domain UDP response")
		}
		size = 7 + int(b[4])
	default:
		t.Fatal("invalid UDP address type")
	}
	if len(b) < size {
		t.Fatal("short UDP response header")
	}
	return b[size:]
}
func (u *nativeRuntimeUDP) marker(t *testing.T, host string, port int, marker, label string) {
	t.Helper()
	payload := []byte(u.fixture.nonce + "/" + label)
	if !bytes.Equal(u.exchange(t, host, port, payload), append([]byte(marker+"|"), payload...)) {
		t.Fatal("UDP marker bytes mismatch")
	}
	u.fixture.expected[marker][string(payload)]++
}

func nativeRuntimeDNSQuestion(t *testing.T) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("guard.invalid.", dns.TypeA)
	m.Id = 0x7431
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func nativeRuntimeDNSAnswer(t *testing.T, answer []byte) {
	t.Helper()
	var m dns.Msg
	if err := m.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if m.Id != 0x7431 || m.Rcode != dns.RcodeSuccess || len(m.Question) != 1 || m.Question[0].Name != "guard.invalid." || len(m.Answer) != 1 {
		t.Fatal("private DNS response metadata mismatch")
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(192, 0, 2, 66)) {
		t.Fatal("private DNS answer mismatch")
	}
}
func (f *nativeRuntimeFixture) dnsTCP(t *testing.T, forced bool) {
	t.Helper()
	var c net.Conn
	if forced {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "managed-input"})
		ctx = session.SetForcedOutboundTagToContext(ctx, "default")
		var err error
		c, err = core.Dial(ctx, f.engine, xnet.TCPDestination(xnet.ParseAddress("198.18.0.2"), 53))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		c, _ = f.connect(t, f.privatePort, 1, "198.18.0.2", 53)
	}
	defer c.Close()
	question := nativeRuntimeDNSQuestion(t)
	if err := nativeRuntimeWriteFrame(c, question); err != nil {
		t.Fatal(err)
	}
	answer, err := nativeRuntimeReadFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	nativeRuntimeDNSAnswer(t, answer)
}
