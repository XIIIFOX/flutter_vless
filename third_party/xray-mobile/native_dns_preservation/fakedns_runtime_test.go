package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func fakeDNSRuntimeDocument(proxyPort, resolverPort int) map[string]any {
	return map[string]any{
		"log":     map[string]any{"loglevel": "none"},
		"fakeDns": map[string]any{"ipPool": "198.19.0.0/16", "poolSize": 1024},
		"dns": map[string]any{"queryStrategy": "UseIPv4", "disableCache": true, "disableFallbackIfMatch": true,
			"servers": []any{
				map[string]any{"address": "fakedns", "domains": []string{"full:fake.invalid"}, "skipFallback": true, "tag": "caller-fake"},
				map[string]any{"address": fmt.Sprintf("tcp://127.0.0.1:%d", resolverPort), "domains": []string{"full:real.invalid"}, "skipFallback": true, "tag": "caller-real"},
			}},
		"outbounds": []any{
			map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"address": "127.0.0.1", "port": proxyPort}},
			map[string]any{"tag": "dns-direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{
				map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": resolverPort},
				map[string]any{"action": "block"},
			}}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"caller-real"}, "outboundTag": "dns-direct"},
			map[string]any{"type": "field", "domain": []string{"full:fake.invalid"}, "network": "tcp,udp", "outboundTag": "proxy"},
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"},
		}},
	}
}

func fakeDNSOpaque(generation int, udp bool) []byte {
	kind := byte(0x81)
	if udp {
		kind = 0x82
	}
	// Binary data has no HTTP/TLS/domain hint. Recovery must come from FakeDNS.
	return bytes.Repeat([]byte{kind, byte(generation), 0, 0xff}, 64)
}

func fakeDNSDomainHeader(port uint16) []byte {
	header := append([]byte{0, 0, 0, 3, byte(len("fake.invalid"))}, "fake.invalid"...)
	return binary.BigEndian.AppendUint16(header, port)
}

func fakeDNSControlReadClosed(n int, err error, goos string) bool {
	var failure net.Error
	if n != 0 || errors.As(err, &failure) && failure.Timeout() {
		return false
	}
	// Match the existing ordinary routing fixture's typed closure boundary.
	// Winsock errno values are distinct from Go's portable syscall constants.
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		goos == "windows" && (errors.Is(err, syscall.Errno(10053)) || errors.Is(err, syscall.Errno(10054)))
}

type fakeDNSControlTimeout struct{ error }

func (fakeDNSControlTimeout) Timeout() bool   { return true }
func (fakeDNSControlTimeout) Temporary() bool { return true }
func (e fakeDNSControlTimeout) Unwrap() error { return e.error }

// Typed fake read results only: no socket, engine or platform operation.
func TestNativeFakeDNSControlClosure(t *testing.T) {
	wrapped := func(err error) error {
		return &net.OpError{Op: "read", Net: "tcp4", Err: &os.SyscallError{Syscall: "wsarecv", Err: err}}
	}
	for _, tc := range []struct {
		name   string
		n      int
		err    error
		goos   string
		closed bool
	}{
		{"eof", 0, wrapped(io.EOF), "windows", true},
		{"broken-pipe", 0, wrapped(syscall.EPIPE), runtime.GOOS, true},
		{"portable-reset", 0, wrapped(syscall.ECONNRESET), runtime.GOOS, true},
		{"windows-reset", 0, wrapped(syscall.Errno(10054)), "windows", true},
		{"windows-abort", 0, wrapped(syscall.Errno(10053)), "windows", true},
		{"foreign-windows-reset", 0, wrapped(syscall.Errno(10054)), "linux", false},
		{"foreign-windows-abort", 0, wrapped(syscall.Errno(10053)), "linux", false},
		{"deadline", 0, wrapped(os.ErrDeadlineExceeded), "windows", false},
		{"timeout-before-eof", 0, wrapped(fakeDNSControlTimeout{io.EOF}), "windows", false},
		{"windows-timeout", 0, wrapped(syscall.Errno(10060)), "windows", false},
		{"unknown", 0, wrapped(syscall.EACCES), "windows", false},
		{"text-is-not-proof", 0, errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), "windows", false},
		{"no-error", 0, nil, "windows", false},
		{"bytes-before-eof", 1, io.EOF, "windows", false},
		{"bytes-before-reset", 1, wrapped(syscall.Errno(10054)), "windows", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fakeDNSControlReadClosed(tc.n, tc.err, tc.goos); got != tc.closed {
				t.Fatalf("control closure=%t, want=%t", got, tc.closed)
			}
		})
	}
}

// One SOCKS carrier owns both transports on the same numeric IPv4 port. The
// UDP relay cannot introduce a separate unqualified physical endpoint.
func fakeDNSSOCKSUpstream(t *testing.T, observed *fixture, associations *atomic.Int64) int {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 1024)
		for {
			n, peer, err := udp.ReadFromUDPAddrPort(packet)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					observed.fail(err)
				}
				return
			}
			header := fakeDNSDomainHeader(18083)
			if associations.Load() == 0 || !peer.Addr().Is4() || n != len(header)+len(fakeDNSOpaque(0, true)) || !bytes.Equal(packet[:len(header)], header) {
				observed.fail(errors.New("FakeDNS UDP lost its recovered domain/port or live association"))
				continue
			}
			payload := packet[len(header):n]
			generation := int(payload[1])
			if generation > 1 || !bytes.Equal(payload, fakeDNSOpaque(generation, true)) {
				observed.fail(errors.New("opaque FakeDNS UDP bytes changed"))
				continue
			}
			observed.record(fmt.Sprintf("UDP/%d", generation))
			_, err = udp.WriteToUDPAddrPort(packet[:n], peer)
			observed.fail(err)
		}
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("FakeDNS UDP carrier did not drain")
		}
	})
	networkListener(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), func(connection net.Conn) {
		var greeting [3]byte
		if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			observed.fail(errors.New("unexpected FakeDNS carrier greeting"))
			return
		}
		if _, err := connection.Write([]byte{5, 0}); err != nil {
			observed.fail(err)
			return
		}
		var request [4]byte
		if _, err := io.ReadFull(connection, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
			observed.fail(errors.New("invalid FakeDNS carrier request"))
			return
		}
		if request[1] == 3 && request[3] == 1 {
			var source [6]byte
			if _, err := io.ReadFull(connection, source[:]); err != nil || source != [6]byte{} {
				observed.fail(errors.New("unexpected FakeDNS UDP association address"))
				return
			}
			associations.Add(1)
			defer associations.Add(-1)
			response := binary.BigEndian.AppendUint16([]byte{5, 0, 0, 1, 127, 0, 0, 1}, uint16(port))
			if _, err := connection.Write(response); err != nil {
				observed.fail(err)
				return
			}
			var extra [1]byte
			n, readErr := connection.Read(extra[:])
			if !fakeDNSControlReadClosed(n, readErr, runtime.GOOS) {
				if readErr == nil {
					readErr = errors.New("missing closure error")
				}
				observed.fail(fmt.Errorf("UDP control did not close explicitly (bytes=%d): %w", n, readErr))
			}
			return
		}
		if request[1] != 1 || request[3] != 3 {
			observed.fail(errors.New("opaque FakeDNS TCP target was not recovered as a domain"))
			return
		}
		target := make([]byte, 1+len("fake.invalid")+2)
		if _, err := io.ReadFull(connection, target); err != nil || !bytes.Equal(target, fakeDNSDomainHeader(18082)[4:]) {
			observed.fail(errors.New("FakeDNS TCP recovered the wrong domain/port"))
			return
		}
		if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
			observed.fail(err)
			return
		}
		payload := make([]byte, len(fakeDNSOpaque(0, false)))
		if _, err := io.ReadFull(connection, payload); err != nil {
			observed.fail(err)
			return
		}
		generation := int(payload[1])
		if generation > 1 || !bytes.Equal(payload, fakeDNSOpaque(generation, false)) {
			observed.fail(errors.New("opaque FakeDNS TCP bytes changed"))
			return
		}
		observed.record(fmt.Sprintf("TCP/%d", generation))
		_, err := connection.Write(payload)
		observed.fail(err)
	})
	return port
}

func testNativeFakeDNS(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("actual FakeDNS Core execution is CI-only")
	}
	var attempts, associations atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("forbidden FakeDNS OS lookup")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if attempts.Load() != 0 {
			t.Error("FakeDNS attempted an OS resolver")
		}
	})
	upstream, realDNS := new(fixture), new(fixture)
	complete := false
	t.Cleanup(func() {
		payloads, failures := upstream.snapshot()
		queries, dnsFailures := realDNS.snapshot()
		if len(failures) != 0 || len(dnsFailures) != 0 || associations.Load() != 0 {
			t.Error("FakeDNS owned fixture failed after drain", payloads, failures, queries, dnsFailures, associations.Load())
		}
		if complete && (!reflect.DeepEqual(payloads, []string{"TCP/0", "UDP/0", "TCP/1", "UDP/1"}) || !reflect.DeepEqual(queries, []string{"real.invalid./1", "real.invalid./1", "real.invalid./1", "real.invalid./1"})) {
			t.Error("FakeDNS payload/query counts changed after drain", payloads, queries)
		}
	})
	proxyPort := fakeDNSSOCKSUpstream(t, upstream, &associations)
	resolver := listener(t, func(connection net.Conn) {
		var size uint16
		if err := binary.Read(connection, binary.BigEndian, &size); err != nil || size == 0 || size > 4096 {
			realDNS.fail(errors.New("invalid bounded real DNS control frame"))
			return
		}
		packet := make([]byte, size)
		if _, err := io.ReadFull(connection, packet); err != nil {
			realDNS.fail(err)
			return
		}
		answer, err := reply(realDNS, packet, "real.invalid", "192.0.2.82")
		if err == nil {
			err = binary.Write(connection, binary.BigEndian, uint16(len(answer)))
		}
		if err == nil {
			_, err = connection.Write(answer)
		}
		realDNS.fail(err) // Exactly one query; never read a post-close/reset frame.
	})
	source := fakeDNSRuntimeDocument(proxyPort, resolver.Addr().(*net.TCPAddr).Port)
	prepared, managedPort := prepare(t, source)
	for generation := range 2 {
		t.Run(fmt.Sprintf("generation%d", generation), func(t *testing.T) {
			built := buildFakeDNSDocument(t, prepared)
			assertManagedFakeDNSSniff(t, built)
			engine, err := core.New(built)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
				deadline := time.Now().Add(3 * time.Second)
				for associations.Load() != 0 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if associations.Load() != 0 {
					t.Error("Core Stop retained its FakeDNS UDP carrier association")
				}
			})
			if err := engine.Start(); err != nil {
				t.Fatal(err)
			}
			var fake netip.Addr
			for _, udp := range []bool{false, true} {
				answer := query(t, managedPort, udp, "fake.invalid", dns.TypeA)
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
					t.Fatal("FakeDNS A allocation missing")
				}
				a, ok := answer.Answer[0].(*dns.A)
				if !ok || !netip.MustParsePrefix("198.19.0.0/16").Contains(netip.MustParseAddr(a.A.String())) {
					t.Fatal("FakeDNS allocation escaped caller pool")
				}
				address := netip.MustParseAddr(a.A.String())
				if fake.IsValid() && fake != address {
					t.Fatal("same engine did not retain its fake domain mapping")
				}
				fake = address
				real := query(t, managedPort, udp, "real.invalid", dns.TypeA)
				if real.Rcode != dns.RcodeSuccess || len(real.Answer) != 1 || real.Answer[0].(*dns.A).A.String() != "192.0.2.82" {
					t.Fatal("mixed tagged real DNS control failed")
				}
				for _, kind := range []uint16{dns.TypeAAAA, dns.TypeMX} {
					answer := query(t, managedPort, udp, "fake.invalid", kind)
					code := dns.RcodeSuccess
					if kind == dns.TypeMX {
						code = dns.RcodeRefused
					}
					if answer.Rcode != code || len(answer.Answer) != 0 {
						t.Fatal("FakeDNS UseIPv4/non-address refusal changed")
					}
				}
			}
			tcp, _ := connect(t, managedPort, 1, netip.AddrPortFrom(fake, 18082), "")
			defer tcp.Close()
			payload := fakeDNSOpaque(generation, false)
			if _, err := tcp.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(tcp, response); err != nil || !bytes.Equal(payload, response) {
				t.Fatal("opaque TCP bytes did not traverse fake IPv4 to recovered domain", err)
			}
			_ = tcp.Close()
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			control, relay := connect(t, managedPort, 3, udp.LocalAddr().(*net.UDPAddr).AddrPort(), "")
			defer control.Close()
			packet := append([]byte{0, 0, 0, 1}, fake.AsSlice()...)
			packet = binary.BigEndian.AppendUint16(packet, 18083)
			packet = append(packet, fakeDNSOpaque(generation, true)...)
			if _, err := udp.WriteToUDPAddrPort(packet, relay); err != nil {
				t.Fatal(err)
			}
			_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 1024)
			n, peer, err := udp.ReadFromUDPAddrPort(buffer)
			want := append(fakeDNSDomainHeader(18083), fakeDNSOpaque(generation, true)...)
			if err != nil || peer != relay || !bytes.Equal(buffer[:n], want) {
				t.Fatal("opaque UDP bytes did not traverse fake IPv4 to recovered domain", err)
			}
		})
		if t.Failed() {
			return
		}
	}
	complete = true
	t.Log("FAKEDNS_OPAQUE_TCP_UDP_PASS generations=2 mixed_real_dns=4 UseIPv4_AAAA_NODATA MX_REFUSED OS_lookups=0")
}
