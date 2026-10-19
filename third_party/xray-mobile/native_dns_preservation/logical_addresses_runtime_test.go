package native_dns_preservation_test

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
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const logicalChildSpec = "FLUTTER_VLESS_LOGICAL_CHILD_SPEC"
const logicalTargetEnvironment = "FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET"
const logicalDormantEnvironment = "FLUTTER_VLESS_FIXTURE_LOGICAL_DORMANT"

type logicalSpec struct {
	Prepared     string
	ManagedPort  int
	InboundPorts []int
}

func logicalPayload() []byte { return bytes.Repeat([]byte("logical-address-"), 2048) }

func requireLogicalRuntime(t *testing.T) {
	t.Helper()
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("logical Address runtime is CI-only")
	}
}

func logicalRuntimeDocument(httpPort, dnsPort int, ports []int) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"dns": map[string]any{"servers": []string{"tcp://9.9.9.9"}},
		"inbounds": []any{
			map[string]any{"tag": "caller-dokodemo", "listen": "127.0.0.1", "port": ports[0], "protocol": "dokodemo-door", "settings": map[string]any{"network": "tcp", "address": "env:" + logicalTargetEnvironment, "rewriteAddress": "env:" + logicalDormantEnvironment, "port": httpPort}},
			map[string]any{"tag": "caller-tunnel", "listen": "127.0.0.1", "port": ports[1], "protocol": "tunnel", "settings": map[string]any{"allowedNetwork": "tcp", "address": nil, "rewriteAddress": "env:" + logicalTargetEnvironment, "rewritePort": httpPort}},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", httpPort, dnsPort)}, map[string]any{"action": "block"}}}},
			map[string]any{"tag": "caller-dns", "protocol": "dns", "settings": map[string]any{"network": "tcp", "address": "env:" + logicalTargetEnvironment, "rewriteAddress": "env:" + logicalDormantEnvironment, "port": dnsPort, "rules": []any{map[string]any{"action": "direct"}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "direct"}}},
			map[string]any{"tag": "caller-dns-fallback", "protocol": "dns", "settings": map[string]any{"rewriteNetwork": "tcp", "address": nil, "rewriteAddress": "env:" + logicalTargetEnvironment, "rewritePort": dnsPort, "rules": []any{map[string]any{"action": "direct"}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "direct"}}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"caller-dokodemo", "caller-tunnel"}, "outboundTag": "direct"},
			map[string]any{"type": "field", "ip": []string{"198.51.100.53/32"}, "port": "53", "network": "tcp", "outboundTag": "caller-dns"},
			map[string]any{"type": "field", "ip": []string{"198.51.100.54/32"}, "port": "53", "network": "tcp", "outboundTag": "caller-dns-fallback"},
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"},
		}},
	}
}

func logicalRuntimeBindings() []dnsAddressBinding {
	return []dnsAddressBinding{{[]string{"inbounds", "0", "settings", "address"}, "127.0.0.1"}, {[]string{"inbounds", "1", "settings", "rewriteAddress"}, "127.0.0.1"}, {[]string{"outbounds", "1", "settings", "address"}, "127.0.0.1"}, {[]string{"outbounds", "2", "settings", "rewriteAddress"}, "127.0.0.1"}}
}

// Origins stay in the parent; the only Core instance belongs to the bounded
// child. The two inbound and two DNS alias forms share the same owned targets.
func testNativeLogicalAddresses(t *testing.T) {
	requireLogicalRuntime(t)
	origin, resolver := new(fixture), new(fixture)
	completed := false
	t.Cleanup(func() {
		if !completed {
			return
		}
		requests, failures := origin.snapshot()
		queries, dnsFailures := resolver.snapshot()
		if !reflect.DeepEqual(requests, []string{"HTTP logical.invalid", "HTTP logical.invalid"}) || len(failures) != 0 ||
			!reflect.DeepEqual(queries, []string{"logical-query.invalid./1", "logical-query.invalid./1"}) || len(dnsFailures) != 0 {
			t.Error("logical handler origin proof failed after drain", requests, failures, queries, dnsFailures)
		}
	})
	httpOrigin := listener(t, func(connection net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			origin.fail(err)
			return
		}
		defer request.Body.Close()
		body, err := io.ReadAll(io.LimitReader(request.Body, int64(len(logicalPayload())+1)))
		if err != nil || request.Method != "POST" || request.Host != "logical.invalid" || request.URL.RequestURI() != "/handler" || !bytes.Equal(body, logicalPayload()) {
			origin.fail(errors.New("logical inbound HTTP request changed"))
			return
		}
		origin.record("HTTP logical.invalid")
		_, err = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
		if err == nil {
			_, err = connection.Write(body)
		}
		origin.fail(err)
	})
	dnsPort := tcpResolver(t, resolver, "logical-query.invalid", "192.0.2.81")
	httpPort := httpOrigin.Addr().(*net.TCPAddr).Port
	var reservations []net.Listener
	var ports []int
	for range 2 {
		reservation, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservation)
		ports = append(ports, reservation.Addr().(*net.TCPAddr).Port)
		defer reservation.Close()
	}
	t.Setenv(logicalTargetEnvironment, "127.0.0.1")
	t.Setenv(logicalDormantEnvironment, "127.0.0.9")
	source := logicalRuntimeDocument(httpPort, dnsPort, ports)
	bindings := logicalRuntimeBindings()
	literal := dnsLiteralControl(t, dnsAddressCase{Config: source, Bindings: bindings})
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	baseline, effective := prepareEndpointAddress(t, literal), prepareEndpointAddress(t, data)
	if !reflect.DeepEqual(baseline, effective) {
		t.Fatal("logical runtime preparation differs from literal control")
	}
	prepared, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "effective.json")
	if err := os.WriteFile(path, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	managed := int(effective["inbounds"].([]any)[0].(map[string]any)["port"].(float64))
	spec, err := json.Marshal(logicalSpec{Prepared: path, ManagedPort: managed, InboundPorts: ports})
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(directory, "child.json")
	if err := os.WriteFile(specPath, spec, 0600); err != nil {
		t.Fatal(err)
	}
	for _, reservation := range reservations {
		if err := reservation.Close(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeLogicalAddressChild$", "-test.v", "-test.timeout=10s")
	command.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if key != logicalChildSpec && key != logicalTargetEnvironment && key != logicalDormantEnvironment && !strings.HasPrefix(key, "XRAY_") && !strings.HasPrefix(key, "XRAY.") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, logicalChildSpec+"="+specPath, logicalTargetEnvironment+"=127.0.0.2", logicalDormantEnvironment+"=127.0.0.2")
	capture := new(dohOutput)
	command.Stdout, command.Stderr = capture, capture
	err = command.Run()
	output, truncated := capture.snapshot()
	if err != nil || truncated || !bytes.Contains(output, []byte("LOGICAL_ADDRESS_CHILD_OK")) || !bytes.Contains(output, []byte("--- PASS: TestNativeLogicalAddressChild")) {
		t.Fatalf("bounded logical Address child failed: %v: %s", err, output)
	}
	completed = true
	t.Logf("LOGICAL_ADDRESS_PAYLOAD_PASS handlers=4 http_requests=2 dns_queries=2 bytes_each=%d", len(logicalPayload()))
}

func TestNativeLogicalAddressChild(t *testing.T) {
	requireLogicalRuntime(t)
	specData, err := os.ReadFile(os.Getenv(logicalChildSpec))
	if err != nil {
		t.Fatal(err)
	}
	var spec logicalSpec
	if len(specData) > 4096 || json.Unmarshal(specData, &spec) != nil || len(spec.InboundPorts) != 2 {
		t.Fatal("invalid owned logical child specification")
	}
	var attempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("forbidden logical handler OS lookup")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if attempts.Load() != 0 {
			t.Error("logical handler attempted OS resolver")
		}
	})
	data, err := os.ReadFile(spec.Prepared)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	for _, port := range spec.InboundPorts {
		func() {
			connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			request, err := http.NewRequest("POST", "http://logical.invalid/handler", bytes.NewReader(logicalPayload()))
			if err != nil {
				t.Fatal(err)
			}
			request.Close = true
			if err := request.Write(connection); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(logicalPayload())+1)))
			if err != nil || response.StatusCode != 200 || !bytes.Equal(body, logicalPayload()) {
				t.Fatal("logical inbound payload changed", err)
			}
		}()
	}
	for _, target := range []string{"198.51.100.53:53", "198.51.100.54:53"} {
		func() {
			connection, _ := connect(t, spec.ManagedPort, 1, netip.MustParseAddrPort(target), "")
			defer connection.Close()
			question := new(dns.Msg)
			question.SetQuestion("logical-query.invalid.", dns.TypeA)
			question.Id = 0x7128
			packet, err := question.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(connection, binary.BigEndian, uint16(len(packet))); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write(packet); err != nil {
				t.Fatal(err)
			}
			var size uint16
			if err := binary.Read(connection, binary.BigEndian, &size); err != nil || size == 0 || size > 4096 {
				t.Fatal("logical DNS response missing", err)
			}
			packet = make([]byte, size)
			if _, err := io.ReadFull(connection, packet); err != nil {
				t.Fatal(err)
			}
			answer := new(dns.Msg)
			if answer.Unpack(packet) != nil || answer.Id != question.Id || !reflect.DeepEqual(answer.Question, question.Question) || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatal("logical DNS identity changed")
			}
			record, ok := answer.Answer[0].(*dns.A)
			if !ok || record.A.String() != "192.0.2.81" {
				t.Fatal("logical DNS answer changed")
			}
		}()
	}
	t.Log("LOGICAL_ADDRESS_CHILD_OK")
}
