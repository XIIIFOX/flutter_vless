package native_dns_preservation_test

import (
	"bufio"
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
	"net/http"
	"net/netip"
	"os"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const ipv6FixtureUser = "00000000-0000-4000-8000-000000000061"

func ipv6RuntimeDocuments(proxyPort int, apiAddress, strategy string) (map[string]any, map[string]any) {
	server := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"protocol": "vless", "tag": "controlled-vless", "listen": "127.0.0.1", "port": proxyPort,
			"settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": ipv6FixtureUser}}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
			"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"::1/128"}}, map[string]any{"action": "block"}}}}},
	}
	client := map[string]any{
		"log":   map[string]any{"loglevel": "none"},
		"api":   map[string]any{"tag": "caller-api", "listen": apiAddress, "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{"system": map[string]any{
			"statsInboundUplink": false, "statsInboundDownlink": false, "statsOutboundUplink": false, "statsOutboundDownlink": false}},
		"dns": map[string]any{"queryStrategy": strategy, "disableCache": true,
			"hosts":   map[string]any{"endpoint.invalid": "127.0.0.2", "payload6.invalid": "::1", "payload4.invalid": "192.0.2.61"},
			"servers": []string{"tcp://9.9.9.9"}},
		"outbounds": []any{
			map[string]any{"protocol": "blackhole", "tag": "default-block"},
			map[string]any{"protocol": "vless", "tag": "proxy", "settings": map[string]any{
				"vnext": []any{map[string]any{"address": "endpoint.invalid", "port": proxyPort,
					"users": []any{map[string]any{"id": ipv6FixtureUser, "encryption": "none"}}}}}},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "ip": []string{"::1/128"}, "network": "tcp,udp", "outboundTag": "proxy"},
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "default-block"},
		}},
	}
	return server, client
}

// Source construction control for the exact runtime documents. Build only;
// no Core instance, listener, resolver or packet engine is created here.
func testIPv6RuntimeDocumentsBuild(t *testing.T) {
	for _, strategy := range []string{"UseIP", "UseIPv4"} {
		server, client := ipv6RuntimeDocuments(18061, "127.0.0.1:18062", strategy)
		for label, document := range map[string]map[string]any{"server": server, "client": client} {
			t.Run("ipv6_vless_"+strategy+"_"+label, func(t *testing.T) {
				data, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				configuration, err := serial.DecodeJSONConfig(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := configuration.Build(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func ipv6EchoOrigin(t *testing.T, observations *fixture, nonce []byte) netip.AddrPort {
	t.Helper()
	connection, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		buffer := make([]byte, 1024)
		for {
			size, peer, err := connection.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					observations.fail(err)
				}
				return
			}
			if !peer.Addr().Is6() || !bytes.Equal(buffer[:size], nonce) {
				observations.fail(errors.New("IPv6 UDP origin received a wrong family or nonce"))
				continue
			}
			observations.record("UDP6")
			if _, err := connection.WriteToUDPAddrPort(buffer[:size], peer); err != nil && !errors.Is(err, net.ErrClosed) {
				observations.fail(err)
			}
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		done := make(chan struct{})
		go func() { worker.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned IPv6 UDP origin did not close")
		}
	})
	return connection.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Called only by TestNativeDNSPreservation in its guarded CI runtime branch.
// A real pinned VLESS server on IPv4 must deliver to real IPv6 TCP/UDP origins.
// This qualifies Core preparation/forwarding; platform TUN and HEV tests remain
// separate requirements and are never inferred from these local proxy bytes.
func testNativeIPv6Payload(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("IPv6 Core runtime is CI-only")
	}
	for _, strategy := range []string{"UseIP", "UseIPv4"} {
		t.Run(strategy, func(t *testing.T) { runNativeIPv6Payload(t, strategy) })
	}
}

func runNativeIPv6Payload(t *testing.T, strategy string) {
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
			t.Error("IPv6 payload attempted OS resolver")
		}
	})
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random[:])
	tcpBody, udpBody := "IPV6_TCP_"+nonce, []byte("IPV6_UDP_"+nonce)
	origin := new(fixture)
	completed := false
	t.Cleanup(func() {
		if completed {
			seen, failures := origin.snapshot()
			if !reflect.DeepEqual(seen, []string{"TCP6", "UDP6"}) || len(failures) != 0 {
				t.Error("IPv6 origin count, nonce or lifecycle mismatch", seen, failures)
			}
		}
	})
	tcp := networkListener(t, "tcp6", "[::1]:0", func(connection net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			origin.fail(err)
			return
		}
		defer request.Body.Close()
		if request.Host != "payload6.invalid" || request.URL.Path != "/"+nonce {
			origin.fail(errors.New("IPv6 HTTP target or nonce changed"))
			return
		}
		origin.record("TCP6")
		_, err = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(tcpBody), tcpBody)
		origin.fail(err)
	})
	tcpTarget := tcp.Addr().(*net.TCPAddr).AddrPort()
	udpTarget := ipv6EchoOrigin(t, origin, udpBody)
	proxyReservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxyReservation.Close() })
	apiReservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiReservation.Close() })
	apiAddress := apiReservation.Addr().String()
	serverDocument, source := ipv6RuntimeDocuments(proxyReservation.Addr().(*net.TCPAddr).Port, apiAddress, strategy)
	newEngine := func(data []byte) *core.Instance {
		configuration, err := serial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		built, err := configuration.Build()
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
		return engine
	}
	serverJSON, err := json.Marshal(serverDocument)
	if err != nil {
		t.Fatal(err)
	}
	server := newEngine(serverJSON)
	_ = proxyReservation.Close()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	prepared, port := prepare(t, source)
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	wantProxy := source["outbounds"].([]any)[1].(map[string]any)
	gotProxy := effective["outbounds"].([]any)[1].(map[string]any)
	wantSettings, _ := json.Marshal(wantProxy["settings"])
	gotSettings, _ := json.Marshal(gotProxy["settings"])
	if gotProxy["tag"] != wantProxy["tag"] || gotProxy["protocol"] != wantProxy["protocol"] || !bytes.Equal(wantSettings, gotSettings) {
		t.Fatal("IPv6 transport's logical proxy settings changed")
	}
	client := newEngine(prepared)
	_ = apiReservation.Close()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	api, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	checkCounters := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		answer, err := statscommand.NewStatsServiceClient(api).QueryStats(ctx, &statscommand.QueryStatsRequest{})
		if err != nil || len(answer.GetStat()) != 0 {
			t.Fatal("caller API unavailable or disabled counters changed", err)
		}
	}
	checkCounters()
	for _, overUDP := range []bool{false, true} {
		answer := query(t, port, overUDP, "payload6.invalid", dns.TypeAAAA)
		if answer.Rcode != dns.RcodeSuccess {
			t.Fatal("caller AAAA strategy failed", answer)
		}
		if strategy == "UseIPv4" {
			if len(answer.Answer) != 0 {
				t.Fatal("caller UseIPv4 strategy was overridden", answer)
			}
		} else if len(answer.Answer) != 1 {
			t.Fatal("caller IPv6 static host was lost", answer)
		} else if record, ok := answer.Answer[0].(*dns.AAAA); !ok || record.AAAA.String() != "::1" {
			t.Fatal("caller IPv6 static host changed", answer)
		}
	}
	connection, _ := connect(t, port, 1, tcpTarget, "")
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET /%s HTTP/1.1\r\nHost: payload6.invalid\r\nConnection: close\r\n\r\n", nonce); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal("IPv6 TCP over IPv4 VLESS failed", err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(data) != tcpBody {
		t.Fatal("IPv6 TCP marker missing", err)
	}
	_ = connection.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	control, relay := connect(t, port, 3, udp.LocalAddr().(*net.UDPAddr).AddrPort(), "")
	defer control.Close()
	header := append([]byte{0, 0, 0, 4}, udpTarget.Addr().AsSlice()...)
	header = binary.BigEndian.AppendUint16(header, udpTarget.Port())
	packet := append(append([]byte{}, header...), udpBody...)
	if _, err := udp.WriteToUDPAddrPort(packet, relay); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	size, peer, err := udp.ReadFromUDPAddrPort(buffer)
	if err != nil || peer != relay || !bytes.Equal(buffer[:size], packet) {
		t.Fatal("IPv6 UDP peer/header/nonce over IPv4 VLESS changed", err)
	}
	_ = control.Close()
	_ = udp.Close()
	checkCounters()
	completed = true
	t.Log("PASS actual IPv6 TCP+UDP through IPv4 VLESS to IPv6 loopback origins; AAAA uses preserved caller strategy; caller API counters remain disabled; no OS resolver")
}
