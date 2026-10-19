package native_dns_preservation_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
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

// This guarded ordinary-Core gate proves the caller's first outbound/default,
// domain block and tagged DNS route. It never stands in for a platform TUN test.
func testNativeDirectOnly(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("direct-only Core runtime is CI-only")
	}
	for _, tc := range directOnlyCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) { runNativeDirectOnly(t, tc.Config) })
	}
}

func testNativeNullDirectTag(t *testing.T) {
	profile := directOnlyCorpus(t)[0].Config
	profile["outbounds"].([]any)[0].(map[string]any)["tag"] = nil
	runNativeDirectOnly(t, profile)
}

func runNativeDirectOnly(t *testing.T, original map[string]any) {
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
			t.Error("direct-only attempted OS resolver")
		}
	})
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random[:])
	origin, resolver := new(fixture), new(fixture)
	completed := false
	// Registered before all sockets/engine: verify after their workers drain.
	t.Cleanup(func() {
		if !completed {
			return
		}
		seen, failures := origin.snapshot()
		queries, dnsFailures := resolver.snapshot()
		if !reflect.DeepEqual(seen, []string{"direct-only.invalid", "direct-only.invalid"}) || len(failures) != 0 {
			t.Error("direct-only HTTP routing/count changed", seen, failures)
		}
		if !reflect.DeepEqual(queries, []string{"direct-only-lookup.invalid./1", "direct-only-lookup.invalid./1"}) || len(dnsFailures) != 0 {
			t.Error("explicit caller TCP DNS selection/count changed", queries, dnsFailures)
		}
	})
	originListener := listener(t, func(connection net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			origin.fail(err)
			return
		}
		defer request.Body.Close()
		origin.record(request.Host)
		if request.Host != "direct-only.invalid" || request.URL.Path != "/"+nonce {
			origin.fail(errors.New("direct-only HTTP target or nonce changed"))
		}
		_, err = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(nonce), nonce)
		origin.fail(err)
	})
	dnsPort := tcpResolver(t, resolver, "direct-only-lookup.invalid", "192.0.2.11")
	apiReservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiReservation.Close() })
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	callerDNS := source["dns"].(map[string]any)
	callerDNS["disableCache"] = true
	callerDNS["servers"] = []string{fmt.Sprintf("tcp://127.0.0.1:%d", dnsPort)}
	// Both domains resolve to the SAME reachable origin: a wrong block route
	// would return the nonce and be observed, rather than time out off-host.
	callerDNS["hosts"] = map[string]any{"direct-only.invalid": "127.0.0.1", "blocked.invalid": "127.0.0.1"}
	source["api"] = map[string]any{"tag": "caller-api", "listen": apiReservation.Addr().String(), "services": []string{"StatsService"}}
	source["stats"] = map[string]any{}
	source["policy"] = map[string]any{"system": map[string]any{
		"statsInboundUplink": false, "statsInboundDownlink": false, "statsOutboundUplink": false, "statsOutboundDownlink": false}}
	prepared, port := prepare(t, source)
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	assertCallerServiceRoots(t, source, effective)
	for index, item := range source["outbounds"].([]any) {
		want := item.(map[string]any)
		got := effective["outbounds"].([]any)[index].(map[string]any)
		if want["tag"] != got["tag"] || want["protocol"] != got["protocol"] || !reflect.DeepEqual(nativeExpectedSettings(want), got["settings"]) {
			t.Fatal("direct-only caller outbound default/order/settings changed")
		}
	}
	configuration, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
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
	_ = apiReservation.Close()
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	api, err := grpc.NewClient(source["api"].(map[string]any)["listen"].(string), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	checkAPI := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		answer, err := statscommand.NewStatsServiceClient(api).QueryStats(ctx, &statscommand.QueryStatsRequest{})
		if err != nil || len(answer.GetStat()) != 0 {
			t.Fatal("direct-only caller API/counters changed", err)
		}
	}
	checkAPI()
	for _, udp := range []bool{false, true} {
		answer := query(t, port, udp, "direct-only-lookup.invalid", dns.TypeA)
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
			t.Fatal("direct-only caller DNS answer missing", answer)
		}
		if record, ok := answer.Answer[0].(*dns.A); !ok || record.A.String() != "192.0.2.11" {
			t.Fatal("direct-only caller DNS answer changed", answer)
		}
	}
	target := originListener.Addr().(*net.TCPAddr).AddrPort()
	request := func(domain string) ([]byte, error) {
		connection, _ := connect(t, port, 1, target, domain)
		defer connection.Close()
		_, err := fmt.Fprintf(connection, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", nonce, domain)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(connection, 4096))
	}
	positive := func() {
		response, err := request("direct-only.invalid")
		if err != nil || !bytes.HasSuffix(response, []byte("\r\n\r\n"+nonce)) || !bytes.HasPrefix(response, []byte("HTTP/1.1 200 OK\r\n")) {
			t.Fatal("direct-only HTTP bytes missing", err)
		}
	}
	positive()
	blocked, err := request("blocked.invalid")
	if len(blocked) != 0 || err != nil && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
		t.Fatal("direct-only block must close without bytes; timeout is not proof", err)
	}
	positive()
	checkAPI()
	completed = true
	t.Log("PASS actual direct-only HTTP/default order + domain block + caller TCP DNS via VIP TCP/UDP; caller API disabled counters; no OS resolver")
}
