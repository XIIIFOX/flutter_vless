package native_dns_preservation_test

// Called only under TestNativeDNSPreservation's CI guard. The two HTTP fronts
// share one actual XHTTP/VLESS server, so upload and download must reach the
// same session through different exact host/port pins. No public server or TUN.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const xhttpChildSpec = "FLUTTER_VLESS_XHTTP_CHILD_SPEC"

type xhttpSpec struct {
	Prepared, Origin string
	Port             int
	Chained          bool
}

func xhttpPayload() []byte { return bytes.Repeat([]byte("XHTTP_SHARED_SOCKET_PAYLOAD_"), 2048) }

func testNativeXHTTPPenetrate(t *testing.T) {
	var systemAttempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden XHTTP OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if systemAttempts.Load() != 0 {
			t.Error("XHTTP attempted an OS resolver")
		}
	})
	observations := new(fixture)
	var stopping atomic.Bool
	complete := false
	// This runs after all owned engines and servers have drained.
	t.Cleanup(func() {
		events, failures := observations.snapshot()
		counts := map[string]int{}
		for _, event := range events {
			counts[event]++
		}
		if !complete {
			t.Logf("XHTTP_FIXTURE_FAILURE events=%d trace=%v failures=%v", len(events), events[:min(len(events), 32)], failures[:min(len(failures), 8)])
			return
		}
		if counts["origin"] != 2 || counts["upload POST"] < 2 || counts["download GET"] < 2 || len(failures) != 0 {
			t.Error("XHTTP did not carry both payloads through the controlled fronts", counts, failures)
		}
	})
	payload := xhttpPayload()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if err != nil || r.Method != "POST" || r.Host != "payload.invalid" || !bytes.Equal(body, payload) {
			observations.fail(errors.New("XHTTP origin request/payload changed"))
			http.Error(w, "fixture mismatch", http.StatusBadRequest)
			return
		}
		observations.record("origin")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err = w.Write(body)
		observations.fail(err)
	}))
	origin.Config.ReadHeaderTimeout = 5 * time.Second
	origin.Start()
	t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
	originAddress := netip.MustParseAddrPort(strings.TrimPrefix(origin.URL, "http://"))

	reservations := []net.Listener{}
	for range 2 {
		reservation, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservation)
		t.Cleanup(func() { _ = reservation.Close() })
	}
	serverPort := reservations[0].Addr().(*net.TCPAddr).Port
	carrierPort := reservations[1].Addr().(*net.TCPAddr).Port
	identity := "11111111-1111-4111-8111-111111111111"
	serverSource := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
		"inbounds": []any{
			map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
				"settings":       map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": identity}}},
				"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/fixture", "host": "backend.invalid", "mode": "packet-up"}}},
			map[string]any{"listen": "127.0.0.1", "port": carrierPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
		},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"domainStrategy": "ForceIPv4"}}},
	}
	serverData, err := json.Marshal(serverSource)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(serverData))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	serverCore, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := serverCore.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, reservation := range reservations {
		if err := reservation.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := serverCore.Start(); err != nil {
		t.Fatal(err)
	}
	backend, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", serverPort))
	front := func(role string) int {
		transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
		proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(backend)
			request.Out.Host = "backend.invalid"
			request.Out.URL.Path = "/fixture" + strings.TrimPrefix(request.In.URL.Path, "/"+role)
		}, ModifyResponse: func(response *http.Response) error {
			observations.record(fmt.Sprintf("%s backend-status=%d", role, response.StatusCode))
			return nil
		}, ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			if !stopping.Load() && request.Context().Err() == nil {
				observations.fail(fmt.Errorf("%s front: %w", role, err))
			}
			http.Error(w, "fixture upstream closed", http.StatusBadGateway)
		}}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != role+".invalid" || !strings.HasPrefix(r.URL.Path, "/"+role+"/") ||
				(role == "upload" && r.Method != "POST") || (role == "download" && r.Method != "GET") {
				observations.fail(fmt.Errorf("%s authority/path/method changed", role))
				http.Error(w, "fixture front mismatch", http.StatusBadRequest)
				return
			}
			observations.record(role + " " + r.Method)
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"+role+"/"), "/")
			observations.record(fmt.Sprintf("%s session=%x", role, sha256.Sum256([]byte(parts[0]))))
			proxy.ServeHTTP(w, r)
		}))
		server.Config.ReadHeaderTimeout = 5 * time.Second
		server.Start()
		t.Cleanup(func() {
			stopping.Store(true)
			server.CloseClientConnections()
			server.Close()
			transport.CloseIdleConnections()
		})
		_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		value, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	uploadPort, downloadPort := front("upload"), front("download")
	allPassed := true
	for _, chained := range []bool{false, true} {
		passed := t.Run(fmt.Sprintf("caller_chain_%t", chained), func(t *testing.T) {
			options := map[string]any{"penetrate": true, "tcpKeepAliveIdle": 30}
			if chained {
				options["dialerProxy"] = "carrier"
			}
			download := map[string]any{"address": "endpoint.invalid", "port": downloadPort, "network": "xhttp",
				"sockopt":       map[string]any{"dialerProxy": "dormant-download-handler", "tcpKeepAliveIdle": 7},
				"xhttpSettings": map[string]any{"path": "/download", "host": "download.invalid"}}
			outbounds := []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"address": "endpoint.invalid", "port": uploadPort, "id": identity, "encryption": "none"},
				"streamSettings": map[string]any{"network": "xhttp", "sockopt": options, "xhttpSettings": map[string]any{
					"path": "/upload", "host": "upload.invalid", "mode": "packet-up", "extra": map[string]any{"downloadSettings": download}}}},
				map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}
			if chained {
				outbounds = append(outbounds, map[string]any{"tag": "carrier", "protocol": "socks", "settings": map[string]any{"address": "endpoint.invalid", "port": carrierPort}})
			}
			source := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{}, "outbounds": outbounds,
				"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.2"}, "queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}}}
			prepared, managedPort := prepare(t, source)
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			stream := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
			actualDownload := stream["xhttpSettings"].(map[string]any)["extra"].(map[string]any)["downloadSettings"]
			want, _ := json.Marshal(download)
			got, _ := json.Marshal(actualDownload)
			if !bytes.Equal(want, got) {
				t.Fatal("XHTTP preparation rewrote the inherited download stream")
			}
			if chained && stream["sockopt"].(map[string]any)["dialerProxy"] != "carrier" {
				t.Fatal("XHTTP parent caller chain changed")
			}
			// Core's system dialer and XHTTP clients keep process-global state.
			// The backend and each prepared client need separate processes, so
			// delayed HTTP workers cannot use another instance's DNS/handlers.
			directory := t.TempDir()
			preparedPath, specPath := filepath.Join(directory, "effective.json"), filepath.Join(directory, "child.json")
			if err := os.WriteFile(preparedPath, prepared, 0600); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(xhttpSpec{Prepared: preparedPath, Origin: originAddress.String(), Port: managedPort, Chained: chained})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(specPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeXHTTPChild$", "-test.v", "-test.timeout=10s")
			command.WaitDelay = time.Second
			for _, entry := range os.Environ() {
				key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
				if key != xhttpChildSpec && !strings.HasPrefix(key, "XRAY_") && !strings.HasPrefix(key, "XRAY.") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, xhttpChildSpec+"="+specPath)
			capture := new(dohOutput)
			command.Stdout, command.Stderr = capture, capture
			err = command.Run()
			output, truncated := capture.snapshot()
			marker := fmt.Sprintf("XHTTP_CHILD_OK chained=%t", chained)
			if err != nil || truncated || !bytes.Contains(output, []byte(marker)) || !bytes.Contains(output, []byte("--- PASS: TestNativeXHTTPChild")) {
				events, failures := observations.snapshot()
				t.Fatalf("isolated XHTTP client failed: %v; events=%d trace=%v failures=%v; child=%s", err,
					len(events), events[:min(len(events), 32)], failures[:min(len(failures), 8)], output)
			}
			t.Logf("XHTTP_PENETRATE_PAYLOAD_PASS chained=%t bytes=%d", chained, len(payload))
		})
		allPassed = passed && allPassed
	}
	complete = allPassed
}

func TestNativeXHTTPChild(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("XHTTP child runtime is CI-only")
	}
	data, err := os.ReadFile(os.Getenv(xhttpChildSpec))
	if err != nil {
		t.Fatal(err)
	}
	var spec xhttpSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	var systemAttempts atomic.Int64
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden XHTTP client OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		// This isolated test process exits next. Keep the trap installed until
		// exit, including any detached XHTTP work after clientCore.Close.
		if systemAttempts.Load() != 0 {
			t.Error("XHTTP client attempted an OS resolver")
		}
	})
	prepared, err := os.ReadFile(spec.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	clientCore, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := clientCore.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := clientCore.Start(); err != nil {
		t.Fatal(err)
	}
	connection, _ := connect(t, spec.Port, 1, netip.MustParseAddrPort(spec.Origin), "")
	defer connection.Close()
	payload := xhttpPayload()
	if _, err := fmt.Fprintf(connection, "POST /echo HTTP/1.1\r\nHost: payload.invalid\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(connection, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal("XHTTP response failed", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatal("XHTTP upload/download bytes changed", err)
	}
	t.Logf("XHTTP_CHILD_OK chained=%t bytes=%d", spec.Chained, len(payload))
}
