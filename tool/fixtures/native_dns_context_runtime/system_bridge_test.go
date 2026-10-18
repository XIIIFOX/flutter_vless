package native_dns_context_runtime_test

// This is a CI-only test of an IN-PROCESS DNS wire primitive. It is not an OS,
// TUN, browser, managed SOCKS or CLI interception qualification. Compile locally;
// execute only in the bounded remote runtime runner.
import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/nativeinstance"
	xnet "github.com/xtls/xray-core/common/net"
)

func systemBridgeUpstream(expected, answer string, entered chan<- time.Time, ended chan<- time.Time) func(*loopServer, net.Conn) error {
	return func(server *loopServer, conn net.Conn) error {
		var size uint16
		if binary.Read(conn, binary.BigEndian, &size) != nil || size == 0 || size > 4096 {
			return errors.New("invalid bounded wire fixture frame")
		}
		packet := make([]byte, size)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return err
		}
		query := &wireDNS.Msg{}
		if query.Unpack(packet) != nil || len(query.Question) != 1 {
			return errors.New("invalid fixture DNS query")
		}
		question := query.Question[0]
		server.record(fmt.Sprintf("%s %d", question.Name, question.Qtype))
		if question.Name == "stall.invalid." && entered != nil {
			select {
			case entered <- time.Now():
			default:
				return errors.New("duplicate stalled wire query")
			}
			defer func() {
				select {
				case ended <- time.Now():
				default:
				}
			}()
			_, err := conn.Read(make([]byte, 1))
			if err == nil {
				return errors.New("unexpected stalled query payload")
			}
			return nil
		}
		response := &wireDNS.Msg{}
		response.SetReply(query)
		switch {
		case question.Name == "missing.invalid.":
			response.Rcode = wireDNS.RcodeNameError
		case question.Name == expected && question.Qtype == wireDNS.TypeA:
			response.Answer = []wireDNS.RR{&wireDNS.A{Hdr: wireDNS.RR_Header{Name: question.Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 77}, A: net.ParseIP(answer)}}
		default:
			response.Rcode = wireDNS.RcodeRefused
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

func systemBridgeDocument(t *testing.T, host string, alpha, beta *loopServer) []byte {
	t.Helper()
	document := map[string]any{
		"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		// Default blackhole makes successful numeric remote-DNS queries causally
		// depend on the caller's original DNS tags and routing rules.
		"outbounds": []any{
			map[string]any{"protocol": "blackhole", "tag": "source-default-block"},
			map[string]any{"protocol": "freedom", "tag": "source-routed", "settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"protocol": "freedom", "tag": "source-native-default"},
		},
		"dns": map[string]any{
			"queryStrategy": "UseIPv4", "disableCache": true, "disableFallbackIfMatch": true,
			"hosts": map[string]any{"full:same-wire.invalid": host},
			"servers": []any{
				map[string]any{"address": "tcp://" + alpha.listener.Addr().String(), "domains": []string{"full:alpha.invalid"}, "skipFallback": true, "tag": "source-alpha-dns", "queryStrategy": "UseIPv4", "timeoutMs": 1000},
				map[string]any{"address": "tcp://" + beta.listener.Addr().String(), "domains": []string{"full:beta.invalid"}, "skipFallback": true, "tag": "source-beta-dns", "queryStrategy": "UseIPv4", "timeoutMs": 1000},
				"localhost",
			},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"source-alpha-dns"}, "outboundTag": "source-routed"},
			map[string]any{"type": "field", "inboundTag": []string{"source-beta-dns"}, "outboundTag": "source-routed"},
		}},
	}
	packet, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func systemBridgeRuntime(t *testing.T, source []byte, server *loopServer) (*nativeinstance.Runtime, *nativeinstance.SystemDNSBridge) {
	t.Helper()
	policy := nativeinstance.Policy{RequiredCapability: nativeinstance.CapabilityID, Resolver: netip.MustParseAddrPort(server.listener.Addr().String()), DefaultOutboundIndex: 2, LookupTimeout: 4 * time.Second,
		SystemDNSBridge: &nativeinstance.SystemDNSBridgePolicy{VirtualIPv4: netip.MustParseAddr("198.18.0.53")}}
	original := append([]byte(nil), source...)
	before := server.activity()
	prepared, err := nativeinstance.PrepareJSON(source, policy)
	if err != nil {
		t.Fatal("trusted wire preparation rejected", err)
	}
	if server.activity() != before || !bytes.Equal(source, original) {
		t.Fatal("wire preparation mutated source or queried resolver")
	}
	instance, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatal("actual wire runtime failed", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := instance.Close(ctx); err != nil {
			t.Error("owned wire runtime did not cleanly drain", err)
		}
	})
	bridge, err := instance.SystemDNSBridge()
	if err != nil {
		t.Fatal("native wire primitive missing", err)
	}
	return instance, bridge
}

func systemBridgeQuery(t *testing.T, bridge *nativeinstance.SystemDNSBridge, name string, kind uint16, tcp bool) *wireDNS.Msg {
	t.Helper()
	query := &wireDNS.Msg{}
	query.SetQuestion(name, kind)
	query.Id = 0x5931
	packet, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddrPort("198.18.0.53:53")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if tcp {
		framed := make([]byte, len(packet)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(packet)))
		copy(framed[2:], packet)
		packet, err = bridge.ExchangeTCP(ctx, destination, framed)
		if err == nil {
			if len(packet) < 2 || int(binary.BigEndian.Uint16(packet[:2])) != len(packet)-2 {
				t.Fatal("bad bounded TCP reply framing")
			}
			packet = packet[2:]
		}
	} else {
		packet, err = bridge.ExchangeUDP(ctx, destination, packet)
	}
	if err != nil {
		t.Fatal("native wire request failed", err)
	}
	response := &wireDNS.Msg{}
	if response.Unpack(packet) != nil || response.Id != query.Id || len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		t.Fatal("native wire reply lost query identity")
	}
	return response
}

func requireSystemBridgeA(t *testing.T, reply *wireDNS.Msg, expected string) {
	t.Helper()
	if reply.Rcode != wireDNS.RcodeSuccess || len(reply.Answer) != 1 {
		t.Fatal("native wire A answer missing")
	}
	a, ok := reply.Answer[0].(*wireDNS.A)
	if !ok || !a.A.Equal(net.ParseIP(expected)) || a.Hdr.Ttl == 0 {
		t.Fatal("native wire A address/TTL differs from caller DNS")
	}
}

func TestAcceptanceNativeDNSSystemBridge(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("Actual Core is CI-only")
	}
	var systemAttempts atomic.Int64
	standard, coreResolver := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden system resolver")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = standard, coreResolver
		if systemAttempts.Load() != 0 {
			t.Error("wire engine attempted OS DNS")
		}
	})
	t.Log("PHASE in-process wire primitive: original caller DNS/hosts/tags/default, no OS/TUN/browser wiring")
	alpha := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("alpha.invalid.", "127.0.0.11", nil, nil))
	beta := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("beta.invalid.", "127.0.0.12", nil, nil))
	entered, ended := make(chan time.Time, 1), make(chan time.Time, 1)
	resolverA := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("default.invalid.", "127.0.0.21", entered, ended))
	resolverB := newLoopServer(t, "tcp4", "127.0.0.1:0", systemBridgeUpstream("default.invalid.", "127.0.0.22", nil, nil))
	sourceA := systemBridgeDocument(t, "127.0.0.7", alpha, beta)
	sourceB := systemBridgeDocument(t, "127.0.0.8", alpha, beta)
	a, bridgeA := systemBridgeRuntime(t, sourceA, resolverA)
	_, bridgeB := systemBridgeRuntime(t, sourceB, resolverB)
	for _, tcp := range []bool{false, true} {
		before := alpha.activity() + beta.activity() + resolverA.activity() + resolverB.activity()
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeA, "same-wire.invalid.", wireDNS.TypeA, tcp), "127.0.0.7")
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeB, "same-wire.invalid.", wireDNS.TypeA, tcp), "127.0.0.8")
		if alpha.activity()+beta.activity()+resolverA.activity()+resolverB.activity() != before {
			t.Fatal("caller hosts lost precedence")
		}
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeA, "default.invalid.", wireDNS.TypeA, tcp), "127.0.0.21")
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeB, "default.invalid.", wireDNS.TypeA, tcp), "127.0.0.22")
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeA, "alpha.invalid.", wireDNS.TypeA, tcp), "127.0.0.11")
		requireSystemBridgeA(t, systemBridgeQuery(t, bridgeB, "beta.invalid.", wireDNS.TypeA, tcp), "127.0.0.12")
	}
	for _, server := range []*loopServer{alpha, beta} {
		observations, failures := server.observations()
		if len(observations) != 2 || len(failures) != 0 {
			t.Fatal("per-domain tagged TCP routing did not reach exact source server")
		}
	}
	before := alpha.activity() + beta.activity() + resolverA.activity() + resolverB.activity()
	for _, kind := range []uint16{wireDNS.TypeAAAA, wireDNS.TypeTXT, wireDNS.TypeSVCB, wireDNS.TypeHTTPS} {
		for _, tcp := range []bool{false, true} {
			reply := systemBridgeQuery(t, bridgeA, "default.invalid.", kind, tcp)
			expected := wireDNS.RcodeRefused
			if kind == wireDNS.TypeAAAA {
				expected = wireDNS.RcodeSuccess
			}
			if reply.Rcode != expected || len(reply.Answer) != 0 {
				t.Fatal("wire non-A policy not explicit")
			}
		}
	}
	if alpha.activity()+beta.activity()+resolverA.activity()+resolverB.activity() != before {
		t.Fatal("AAAA/non-IP wire query escaped to resolver")
	}
	if reply := systemBridgeQuery(t, bridgeB, "missing.invalid.", wireDNS.TypeA, false); reply.Rcode != wireDNS.RcodeNameError {
		t.Fatal("caller NXDOMAIN RCode not preserved")
	}
	// Invalid candidate is rejected structurally and cannot retire either owner.
	if candidate, err := nativeinstance.PrepareJSON(sourceA, nativeinstance.Policy{RequiredCapability: "wrong-capability"}); candidate != nil || err == nil {
		t.Fatal("invalid wire candidate accepted")
	}
	requireSystemBridgeA(t, systemBridgeQuery(t, bridgeA, "same-wire.invalid.", wireDNS.TypeA, false), "127.0.0.7")
	requireSystemBridgeA(t, systemBridgeQuery(t, bridgeB, "same-wire.invalid.", wireDNS.TypeA, true), "127.0.0.8")
	t.Log("PHASE in-process wire primitive: bounded unsupported types, independent owners, close cancels actual numeric resolver socket")
	query := &wireDNS.Msg{}
	query.SetQuestion("stall.invalid.", wireDNS.TypeA)
	packet, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	requestDeadline := time.Now().Add(4 * time.Second)
	operation, cancel := context.WithDeadline(context.Background(), requestDeadline)
	defer cancel()
	requestEnded := make(chan error, 1)
	var requestWait sync.WaitGroup
	requestWait.Add(1)
	go func() {
		defer requestWait.Done()
		_, err := bridgeA.ExchangeUDP(operation, netip.MustParseAddrPort("198.18.0.53:53"), packet)
		requestEnded <- err
	}()
	// Retain ownership on every assertion exit: cancel/close owner before waiting
	// for the request goroutine, while fixture cleanup closes any final socket.
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = a.Close(ctx)
		done := make(chan struct{})
		go func() { requestWait.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned wire request did not end")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual wire resolver did not stall")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	err = a.Close(closeCtx)
	closeCancel()
	if err != nil {
		t.Fatal("wire owner cleanup failed", err)
	}
	select {
	case end := <-ended:
		if !end.Before(requestDeadline) {
			t.Fatal("socket ended by request timeout rather than owner Close")
		}
	case <-time.After(time.Second):
		t.Fatal("wire owner returned before resolver socket ended")
	}
	select {
	case err := <-requestEnded:
		if err == nil {
			t.Fatal("closed wire operation published late result")
		}
	case <-time.After(time.Second):
		t.Fatal("closed wire operation still waiting")
	}
	before = resolverA.activity()
	if _, err := bridgeA.ExchangeUDP(context.Background(), netip.MustParseAddrPort("198.18.0.53:53"), packet); !errors.Is(err, nativeinstance.ErrClosed) {
		t.Fatal("old wire handle accepted after close")
	}
	if resolverA.activity() != before {
		t.Fatal("old wire handle issued physical query")
	}
	requireSystemBridgeA(t, systemBridgeQuery(t, bridgeB, "default.invalid.", wireDNS.TypeA, true), "127.0.0.22")
	if systemAttempts.Load() != 0 {
		t.Fatal("wire primitive attempted system DNS")
	}
}
