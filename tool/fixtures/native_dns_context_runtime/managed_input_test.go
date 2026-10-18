package native_dns_context_runtime_test

// Actual Core managed SOCKS consumer, remote CI ONLY. No TUN, browser, system
// DNS settings, host routes, production entry or ordinary UDP qualification.
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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/nativeinstance"
	xnet "github.com/xtls/xray-core/common/net"
)

func managedPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	result := make([]int, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		result = append(result, listener.Addr().(*net.TCPAddr).Port)
	}
	return result // Test allocation only; production atomic port acquisition pending.
}
func managedAuth(port int, user, password string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{5, 2}) {
		return nil, errors.New("SOCKS password method refused")
	}
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err = conn.Write(auth); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{1, 0}) {
		return nil, errors.New("SOCKS native authentication refused")
	}
	failed = false
	return conn, nil
}
func managedConnect(t *testing.T, port int, user, password string, command byte, target netip.AddrPort) (net.Conn, netip.AddrPort) {
	t.Helper()
	conn, err := managedAuth(port, user, password)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{5, command, 0, 1}
	ip := target.Addr().As4()
	packet = append(packet, ip[:]...)
	packet = binary.BigEndian.AppendUint16(packet, target.Port())
	if _, err = conn.Write(packet); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		_ = conn.Close()
		t.Fatal("managed SOCKS command failed", err)
	}
	endpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{reply[4], reply[5], reply[6], reply[7]}), binary.BigEndian.Uint16(reply[8:]))
	return conn, endpoint
}
func managedDNSPacket(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	q := &wireDNS.Msg{}
	q.SetQuestion(name, wireDNS.TypeA)
	q.Id = id
	packet, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func managedDNSResponse(t *testing.T, packet []byte, id uint16, expected string) {
	t.Helper()
	reply := &wireDNS.Msg{}
	if reply.Unpack(packet) != nil || reply.Id != id {
		t.Fatal("managed packet identity changed")
	}
	requireSystemBridgeA(t, reply, expected)
}
func managedTCPDNS(t *testing.T, port int, name, expected string) {
	t.Helper()
	conn, _ := managedConnect(t, port, "native-user", "native-password", 1, netip.MustParseAddrPort("198.18.0.53:53"))
	defer conn.Close()
	packet := managedDNSPacket(t, 0x4831, name)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(packet))); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	var size uint16
	if binary.Read(conn, binary.BigEndian, &size) != nil || size == 0 || size > 4096 {
		t.Fatal("managed TCP DNS response missing")
	}
	packet = make([]byte, size)
	if _, err := io.ReadFull(conn, packet); err != nil {
		t.Fatal(err)
	}
	managedDNSResponse(t, packet, 0x4831, expected)
}
func managedUDPSend(t *testing.T, conn *net.UDPConn, target netip.AddrPort, id uint16, name string) {
	t.Helper()
	packet := []byte{0, 0, 0, 1}
	ip := target.Addr().As4()
	packet = append(packet, ip[:]...)
	packet = binary.BigEndian.AppendUint16(packet, target.Port())
	packet = append(packet, managedDNSPacket(t, id, name)...)
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
}
func managedUDPRead(t *testing.T, conn *net.UDPConn, id uint16, expected string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	packet := make([]byte, 4110)
	size, err := conn.Read(packet)
	if err != nil || size < 10 {
		t.Fatal("managed UDP DNS response missing", err)
	}
	packet = packet[:size]
	if !bytes.Equal(packet[:10], []byte{0, 0, 0, 1, 198, 18, 0, 53, 0, 53}) {
		t.Fatal("managed UDP response lost exact virtual endpoint")
	}
	managedDNSResponse(t, packet[10:], id, expected)
}
func startManagedRuntime(t *testing.T, source []byte, resolver *loopServer, port int) *nativeinstance.Runtime {
	t.Helper()
	p, err := nativeinstance.PrepareJSON(source, nativeinstance.Policy{RequiredCapability: nativeinstance.CapabilityID, Resolver: netip.MustParseAddrPort(resolver.listener.Addr().String()), DefaultOutboundIndex: 2, LookupTimeout: 4 * time.Second,
		SystemDNSBridge: &nativeinstance.SystemDNSBridgePolicy{VirtualIPv4: netip.MustParseAddr("198.18.0.53")}, ManagedInput: &nativeinstance.ManagedInputPolicy{Listen: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), Username: "native-user", Password: "native-password"}})
	if err != nil {
		t.Fatal("managed native preparation failed", err)
	}
	r, err := p.Start(context.Background())
	if err != nil {
		t.Fatal("actual managed input failed", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error("managed runtime cleanup failed", err)
		}
	})
	return r
}
func managedSource(t *testing.T, host string, alpha, beta *loopServer, callerPort, ordinaryPort int) []byte {
	t.Helper()
	source := systemBridgeDocument(t, host, alpha, beta)
	var object map[string]any
	if json.Unmarshal(source, &object) != nil {
		t.Fatal("fixture JSON decode")
	}
	object["inbounds"] = []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": callerPort, "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "caller-user", "pass": "caller-password"}}}}}
	// The later imported callback stalls during its handshake. Keep the server's
	// natural expiry well beyond the fixed four-second closure-observation bound.
	object["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 20}}}
	router := object["routing"].(map[string]any)
	router["rules"] = append(router["rules"].([]any), map[string]any{"type": "field", "network": "tcp", "port": ordinaryPort, "outboundTag": "source-routed"})
	packet, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestAcceptanceNativeDNSManagedInput(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("Actual Core is CI-only")
	}
	var systemAttempts atomic.Int64
	previousStandard, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden managed system resolver")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previousStandard, previousCore
		if systemAttempts.Load() != 0 {
			t.Error("managed input attempted system resolver")
		}
	})
	t.Log("PHASE managed authenticated SOCKS: exact private input, TCP plus per-packet UDP DNS, no OS/TUN wiring")
	alpha := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("alpha.invalid.", "127.0.0.11", nil, nil))
	beta := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("beta.invalid.", "127.0.0.12", nil, nil))
	entered, ended := make(chan time.Time, 1), make(chan time.Time, 1)
	resolverA := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("default.invalid.", "127.0.0.21", entered, ended))
	resolverB := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("default.invalid.", "127.0.0.22", nil, nil))
	origin := newLoopServer(t, "tcp4", "127.0.0.1:0", markerProtocol("unused", "MANAGED_ORDINARY_TCP"))
	ordinaryPort := origin.listener.Addr().(*net.TCPAddr).Port
	ports := managedPorts(t, 4)
	a := startManagedRuntime(t, managedSource(t, "127.0.0.7", alpha, beta, ports[0], ordinaryPort), resolverA, ports[1])
	_ = startManagedRuntime(t, managedSource(t, "127.0.0.8", alpha, beta, ports[2], ordinaryPort), resolverB, ports[3])
	if conn, err := managedAuth(ports[1], "wrong-user", "wrong-password"); err == nil {
		_ = conn.Close()
		t.Fatal("wrong managed credentials admitted")
	}
	managedTCPDNS(t, ports[1], "same-wire.invalid.", "127.0.0.7")
	managedTCPDNS(t, ports[3], "same-wire.invalid.", "127.0.0.8")
	managedTCPDNS(t, ports[1], "alpha.invalid.", "127.0.0.11")
	// Imported caller input has the same empty tag but no exact private binding.
	caller, _ := managedConnect(t, ports[0], "caller-user", "caller-password", 1, netip.MustParseAddrPort("198.18.0.53:53"))
	packet := managedDNSPacket(t, 99, "same-wire.invalid.")
	_ = caller.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_ = binary.Write(caller, binary.BigEndian, uint16(len(packet)))
	_, _ = caller.Write(packet)
	one := make([]byte, 1)
	if _, err := caller.Read(one); err == nil {
		_ = caller.Close()
		t.Fatal("caller tag acquired private DNS path")
	}
	_ = caller.Close()
	// Ordinary TCP still follows the original caller router, whose default is a
	// blackhole; success therefore requires the source port rule and freedom.
	httpConn, _ := managedConnect(t, ports[1], "native-user", "native-password", 1, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ordinaryPort)))
	if _, err := fmt.Fprint(httpConn, "GET /managed HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(httpConn), nil)
	if err != nil {
		_ = httpConn.Close()
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	_ = httpConn.Close()
	if err != nil || string(body) != "MANAGED_ORDINARY_TCP" {
		t.Fatal("ordinary managed TCP did not retain source routing")
	}
	control, udpEndpoint := managedConnect(t, ports[1], "native-user", "native-password", 3, netip.MustParseAddrPort("0.0.0.0:0"))
	defer control.Close()
	udpConn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(udpEndpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	// A cached UDP ray must demux each packet, including ordinary→DNS→ordinary→DNS.
	ordinary := netip.MustParseAddrPort("198.18.0.54:53")
	virtual := netip.MustParseAddrPort("198.18.0.53:53")
	managedUDPSend(t, udpConn, ordinary, 100, "same-wire.invalid.")
	managedUDPSend(t, udpConn, virtual, 101, "same-wire.invalid.")
	managedUDPRead(t, udpConn, 101, "127.0.0.7")
	managedUDPSend(t, udpConn, ordinary, 102, "same-wire.invalid.")
	managedUDPSend(t, udpConn, virtual, 103, "beta.invalid.")
	managedUDPRead(t, udpConn, 103, "127.0.0.12")
	// This authenticated imported source callback now stalls waiting for its
	// SOCKS command. Core's listener Close alone does not own that accepted socket.
	// The native wrapper must track it without granting any private DNS capsule.
	idleStarted := time.Now()
	idleCaller, err := managedAuth(ports[0], "caller-user", "caller-password")
	if err != nil {
		t.Fatal("imported idle callback did not authenticate", err)
	}
	defer idleCaller.Close()
	t.Log("PHASE managed input: owner Close drains actual TCP control, UDP Associate listener and stalled resolver; owner B survives")
	queryDeadline := time.Now().Add(4 * time.Second)
	managedUDPSend(t, udpConn, virtual, 104, "stall.invalid.")
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("managed actual UDP DNS did not enter resolver")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	err = a.Close(ctx)
	cancel()
	if err != nil {
		t.Fatal("managed owner Close failed", err)
	}
	select {
	case end := <-ended:
		if !end.Before(queryDeadline) {
			t.Fatal("managed resolver ended by natural timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("managed resolver socket outlived Close")
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := control.Read(one); !errors.Is(err, io.EOF) {
		t.Fatal("managed TCP control did not reach EOF on owner Close", err)
	}
	_ = idleCaller.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idleCaller.Read(one); !errors.Is(err, io.EOF) {
		t.Fatal("imported idle callback did not reach EOF on owner Close", err)
	}
	if !time.Now().Before(idleStarted.Add(4 * time.Second)) {
		t.Fatal("imported callback closure was not observed before handshake expiry margin")
	}
	// Close must wait for the full socks.Process callback, whose finalizer owns
	// this exact temporary UDP listener. Rebinding is a causal closure check.
	rebound, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(udpEndpoint))
	if err != nil {
		t.Fatal("managed UDP Associate listener still owned after Close", err)
	}
	_ = rebound.Close()
	if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", ports[1]), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("closed managed TCP listener still accepting")
	}
	managedTCPDNS(t, ports[3], "default.invalid.", "127.0.0.22")
}
