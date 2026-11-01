package dispatcher_test

// CI-only data-plane test. A numeric SOCKS CONNECT carries a real TLS
// ClientHello, and the production native routing owner selects an independent
// direct origin or SOCKS proxy. Neither a domain CONNECT nor a mocked router can
// satisfy this test. All listeners are owned loopback sockets; no system route,
// DNS setting, VPN, public server or cloud account is used.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
)

const sniffRouteHost = "sniff-route.invalid"

// Wrong/missing SNI and disabled sniffing are positive default-path controls.
// The proxy verifies the exact numeric target, proving routeOnly did not
// replace it with SNI. Real IPv6 ::1 payload is separate from NAT64 address
// carriage: the latter deliberately does not claim a NAT64 translator exists.
func TestNativeVPNRoutingRuntimeLiteralIPTLS(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("literal-IP TLS routing runtime is CI-only")
	}
	var resolverCalls atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		resolverCalls.Add(1)
		return nil, errors.New("literal-IP TLS fixture forbids system DNS")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if resolverCalls.Load() != 0 {
			t.Error("literal-IP routing attempted system DNS")
		}
	})
	for _, family := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		for _, defaultTag := range []string{"direct", "proxy"} {
			for _, sniff := range []bool{true, false} {
				t.Run(family.network+"/default-"+defaultTag+"/sniff-"+strconv.FormatBool(sniff), func(t *testing.T) {
					f := newSniffRoutingFixture(t, family.network, family.host, defaultTag, sniff)
					for index, sni := range []string{sniffRouteHost, "unmatched.invalid", "127.0.0.1"} {
						expected := defaultTag
						if sniff && sni == sniffRouteHost {
							expected = "proxy"
							if defaultTag == "proxy" {
								expected = "direct"
							}
						}
						f.request(t, family.host, sni, fmt.Sprintf("request-%d", index), expected)
					}
				})
			}
		}
	}
	t.Run("nat64-address-carriage-not-translation", func(t *testing.T) {
		f := newSniffRoutingFixture(t, "tcp4", "127.0.0.1", "proxy", true)
		for index, ip := range []string{"64:ff9b::c000:201", "64:ff9b:1::c000:201"} {
			f.request(t, ip, "unmatched.invalid", fmt.Sprintf("nat64-%d", index), "proxy")
		}
	})
}

type sniffRoutingServer struct {
	listener net.Listener
	mu       sync.Mutex
	active   map[net.Conn]bool
	closed   bool
	seen     map[string]int
	failures []string
	wg       sync.WaitGroup
}

func newSniffRoutingServer(t *testing.T, network, address string, serve func(net.Conn) (string, error)) *sniffRoutingServer {
	t.Helper()
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal("required loopback listener unavailable", err)
	}
	s := &sniffRoutingServer{listener: l, active: map[net.Conn]bool{}, seen: map[string]int{}}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = c.Close()
				return
			}
			s.active[c] = true
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer c.Close()
				defer func() { s.mu.Lock(); delete(s.active, c); s.mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				label, err := serve(c)
				s.mu.Lock()
				defer s.mu.Unlock()
				if err != nil {
					s.failures = append(s.failures, err.Error())
				} else {
					s.seen[label]++
				}
			}()
		}
	}()
	t.Cleanup(func() {
		if !s.drain(time.Now().Add(3 * time.Second)) {
			t.Error("TLS/SOCKS fixture workers did not drain")
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.failures) != 0 {
			t.Errorf("TLS/SOCKS fixture failures: %v", s.failures)
		}
	})
	return s
}

func (s *sniffRoutingServer) drain(until time.Time) bool {
	s.mu.Lock()
	s.closed = true
	for c := range s.active {
		_ = c.Close()
	}
	s.mu.Unlock()
	_ = s.listener.Close()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(time.Until(until)):
		return false
	}
}

type sniffRoutingFixture struct {
	privatePort, targetPort int
	certificate             tls.Certificate
	roots                   *x509.CertPool
	origins                 map[string]*sniffRoutingServer
	expected                map[string]map[string]int
	proxyTargets            sync.Map
}

func newSniffRoutingFixture(t *testing.T, network, host, defaultTag string, sniff bool) *sniffRoutingFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-loopback-fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{sniffRouteHost, "unmatched.invalid"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &sniffRoutingFixture{certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots: x509.NewCertPool(),
		origins: map[string]*sniffRoutingServer{}, expected: map[string]map[string]int{"direct": {}, "proxy": {}}}
	f.roots.AddCert(parsed)
	serveTLS := func(marker string, c net.Conn) (string, error) {
		secured := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.certificate}, MinVersion: tls.VersionTLS13})
		defer secured.Close()
		request, err := http.ReadRequest(bufio.NewReader(secured))
		if err != nil {
			return "", err
		}
		defer request.Body.Close()
		label := strings.TrimPrefix(request.URL.Path, "/")
		if request.Method != "GET" || label == "" || request.Host != "fixture.invalid" {
			return "", errors.New("unexpected TLS HTTP request")
		}
		body := marker + "|" + label
		_, err = fmt.Fprintf(secured, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		return label, err
	}
	f.origins["direct"] = newSniffRoutingServer(t, network, net.JoinHostPort(host, "0"), func(c net.Conn) (string, error) { return serveTLS("direct", c) })
	f.targetPort = f.origins["direct"].listener.Addr().(*net.TCPAddr).Port
	f.origins["proxy"] = newSniffRoutingServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) (string, error) {
		// This independent SOCKS endpoint does not resolve or forward anything.
		// It verifies the numeric target preserved by routeOnly before serving
		// its different TLS marker on the same byte stream.
		var greeting [3]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			return "", fmt.Errorf("proxy SOCKS greeting mismatch: %v", err)
		}
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return "", err
		}
		var request [4]byte
		if _, err := io.ReadFull(c, request[:]); err != nil || !bytes.Equal(request[:3], []byte{5, 1, 0}) {
			return "", fmt.Errorf("proxy SOCKS CONNECT mismatch: %v", err)
		}
		length := 0
		switch request[3] {
		case 1:
			length = 4
		case 4:
			length = 16
		default:
			return "", errors.New("routeOnly replaced literal SOCKS destination with SNI")
		}
		address := make([]byte, length+2)
		if _, err := io.ReadFull(c, address); err != nil {
			return "", err
		}
		target := net.JoinHostPort(net.IP(address[:length]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(address[length:]))))
		if _, permitted := f.proxyTargets.Load(target); !permitted {
			return "", errors.New("proxy received altered numeric destination/port")
		}
		if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
			return "", err
		}
		return serveTLS("proxy", c)
	})
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	f.privatePort = reservation.Addr().(*net.TCPAddr).Port
	ruleTag := "proxy"
	if defaultTag == "proxy" {
		ruleTag = "direct"
	}
	document := map[string]any{"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"tag": "managed-input", "listen": "127.0.0.1", "port": f.privatePort, "protocol": "socks",
			"settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": nativeRuntimeUser, "pass": nativeRuntimePassword}}},
			"sniffing": map[string]any{"enabled": sniff, "destOverride": []string{"tls"}, "routeOnly": true}}},
		"outbounds": []any{map[string]any{"protocol": "blackhole", "tag": "ordinary-default-must-not-win"},
			map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32", "::1/128"}}, map[string]any{"action": "block"}}}},
			map[string]any{"protocol": "socks", "tag": "proxy", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": f.origins["proxy"].listener.Addr().(*net.TCPAddr).Port}}}}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"caller-input"}, "domain": []string{"full:" + sniffRouteHost}, "outboundTag": ruleTag}}}}
	data, err := json.Marshal(document)
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
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: compiled.Inbound[0], ManagedTag: "managed-input", AuthUser: nativeRuntimeUser,
		AliasEnabled: true, InboundAlias: "caller-input", DefaultOutboundTag: defaultTag})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			_ = owner.Close()
		}
	}()
	ctx, err := dispatcher.ContextWithNativeVPNRouting(context.Background(), owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.NewWithContext(ctx, compiled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		until := time.Now().Add(3 * time.Second)
		_ = owner.Close()
		done := make(chan error, 1)
		go func() { done <- engine.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error("sniff routing Core close", err)
			}
		case <-time.After(time.Until(until)):
			t.Error("sniff routing Core did not close")
		}
		for marker, origin := range f.origins {
			if !origin.drain(until) {
				t.Error("sniff routing fixture did not drain")
			}
			origin.mu.Lock()
			if len(origin.seen) != len(f.expected[marker]) {
				t.Errorf("%s route request count mismatch: got=%d want=%d", marker, len(origin.seen), len(f.expected[marker]))
			}
			for label, count := range f.expected[marker] {
				if origin.seen[label] != count {
					t.Errorf("%s route marker count mismatch for %s", marker, label)
				}
			}
			origin.mu.Unlock()
		}
	})
	if err := owner.Seal(engine); err != nil {
		t.Fatal(err)
	}
	_ = reservation.Close()
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *sniffRoutingFixture) request(t *testing.T, target, sni, label, expected string) {
	t.Helper()
	f.proxyTargets.Store(net.JoinHostPort(target, strconv.Itoa(f.targetPort)), true)
	// The shared authenticated helper deliberately uses only numeric IPv4 or
	// IPv6 here. An IPv6-aware CONNECT encoder is needed because the older
	// marker fixture intentionally only distinguishes IPv4 and domain names.
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.privatePort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatal("private method mismatch", err)
	}
	auth := append([]byte{1, byte(len(nativeRuntimeUser))}, nativeRuntimeUser...)
	auth = append(auth, byte(len(nativeRuntimePassword)))
	auth = append(auth, nativeRuntimePassword...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, response[:]); err != nil || response != [2]byte{1, 0} {
		t.Fatal("private auth mismatch", err)
	}
	ip := net.ParseIP(target)
	if ip == nil {
		t.Fatal("fixture requires a literal target")
	}
	address := append([]byte{5, 1, 0, 4}, ip.To16()...)
	if ip4 := ip.To4(); ip4 != nil {
		address = append([]byte{5, 1, 0, 1}, ip4...)
	}
	if _, err := c.Write(binary.BigEndian.AppendUint16(address, uint16(f.targetPort))); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("private numeric CONNECT mismatch", err)
	}
	secured := tls.Client(c, &tls.Config{ServerName: sni, RootCAs: f.roots, MinVersion: tls.VersionTLS13})
	defer secured.Close()
	if _, err := fmt.Fprintf(secured, "GET /%s HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n", label); err != nil {
		t.Fatal("real TLS handshake/write failed", err)
	}
	result, err := http.ReadResponse(bufio.NewReader(secured), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, 256))
	if err != nil || result.StatusCode != 200 || string(body) != expected+"|"+label {
		t.Fatalf("literal-IP TLS wrong route: got=%q want=%q error=%v", body, expected+"|"+label, err)
	}
	f.expected[expected][label]++
}
