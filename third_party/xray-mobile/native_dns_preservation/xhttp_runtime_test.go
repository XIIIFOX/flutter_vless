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
	"reflect"
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

func xhttpHeaderData() map[string]string {
	return map[string]string{"allowInsecure": "literal-header-value", "network": "MiXeD-CaSe",
		"xHTTPSettings": "literal-alias-name", "type": "xicmp", "Origin": "quic+local://literal.invalid"}
}

type xhttpSpec struct {
	Prepared, Origin string
	Port             int
	Chained          bool
}

func xhttpPayload() []byte { return bytes.Repeat([]byte("XHTTP_SHARED_SOCKET_PAYLOAD_"), 2048) }

// Observe the bytes actually read by the forwarding transport without buffering
// or changing the original reader's Read/Close results.
type xhttpObservedBody struct {
	io.ReadCloser
	consumed atomic.Int64
	finished atomic.Bool
	observe  func(string, int64, error)
}

func (b *xhttpObservedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.consumed.Add(int64(n))
	if err != nil && b.finished.CompareAndSwap(false, true) {
		b.observe("read-end", b.consumed.Load(), err)
	}
	return n, err
}

func (b *xhttpObservedBody) Close() error {
	err := b.ReadCloser.Close()
	if b.finished.CompareAndSwap(false, true) {
		b.observe("close", b.consumed.Load(), err)
	}
	return err
}

func xhttpLogFailure(t *testing.T, path string) {
	t.Helper()
	log, err := os.Open(path)
	if err != nil {
		t.Logf("XHTTP_BACKEND_LOG unavailable error-class=%T", err)
		return
	}
	defer log.Close()
	info, err := log.Stat()
	if err != nil {
		t.Logf("XHTTP_BACKEND_LOG stat error-class=%T", err)
		return
	}
	if info.Size() > 64<<10 {
		if _, err := log.Seek(info.Size()-(64<<10), io.SeekStart); err != nil {
			t.Logf("XHTTP_BACKEND_LOG seek error-class=%T", err)
			return
		}
	}
	data, err := io.ReadAll(io.LimitReader(log, 64<<10))
	if err != nil {
		t.Logf("XHTTP_BACKEND_LOG read error-class=%T", err)
		return
	}
	if len(data) > 8<<10 {
		data = data[len(data)-(8<<10):]
	}
	t.Logf("XHTTP_BACKEND_LOG tail=%s", data)
}

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
	var originConnections, echRequests atomic.Int64
	var stopping atomic.Bool
	complete := false
	// Register this directory before the final observer so the log survives
	// until every later Core/server cleanup has completed.
	backendLog := filepath.Join(t.TempDir(), "backend.log")
	// This runs after all owned engines and servers have drained.
	t.Cleanup(func() {
		events, failures := observations.snapshot()
		counts := map[string]int{}
		for _, event := range events {
			counts[event]++
		}
		if complete && (counts["origin"] != 3 || counts["upload POST"] < 3 || counts["download GET"] < 3 || len(failures) != 0) {
			t.Error("XHTTP did not carry all three payloads through the controlled fronts", counts, failures)
		}
		if complete && (originConnections.Load() != 3 || echRequests.Load() != 0) {
			t.Error("dormant ECH attempted an extra origin connection/request", originConnections.Load(), echRequests.Load())
		}
		if !complete || t.Failed() {
			t.Logf("XHTTP_FIXTURE_FAILURE events=%d trace=%v failures=%v", len(events), events[:min(len(events), 48)], failures[:min(len(failures), 8)])
			xhttpLogFailure(t, backendLog)
		}
	})
	payload := xhttpPayload()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ech-must-not-run" || r.Method == "PRI" {
			echRequests.Add(1)
			observations.fail(errors.New("dormant ECH request reached existing origin"))
			http.Error(w, "dormant ECH", http.StatusBadRequest)
			return
		}
		observations.record(fmt.Sprintf("origin-entry content-length=%d", r.ContentLength))
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if err != nil || r.Method != "POST" || r.Host != "payload.invalid" || !bytes.Equal(body, payload) {
			observations.fail(fmt.Errorf("XHTTP origin mismatch bytes=%d expected=%d error-class=%T method-match=%t host-match=%t payload-match=%t",
				len(body), len(payload), err, r.Method == "POST", r.Host == "payload.invalid", bytes.Equal(body, payload)))
			http.Error(w, "fixture mismatch", http.StatusBadRequest)
			return
		}
		observations.record("origin")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err = w.Write(body)
		observations.fail(err)
	}))
	origin.Config.ReadHeaderTimeout = 5 * time.Second
	// Each isolated client makes exactly one CONNECT plus its one HTTP POST
	// to this origin. An ECH h2c dial must create an extra TCP connection even
	// when net/http rejects its HTTP/2 preface before invoking the handler.
	origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			originConnections.Add(1)
		}
	}
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
		"log": map[string]any{"loglevel": "info", "access": "none", "error": backendLog, "dnsLog": false},
		"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
		"inbounds": []any{
			map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
				"settings":       map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": identity}}},
				"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/fixture", "host": "backend.invalid", "mode": "packet-up"}}},
			map[string]any{"listen": "127.0.0.1", "port": carrierPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
		},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
			"domainStrategy": "ForceIPv4",
			// VLESS normally blocks private targets. Only this owned origin is
			// exempt; every unmatched target keeps Core's existing defaults.
			"finalRules": []any{map[string]any{"action": "allow", "network": "tcp",
				"ip": []string{originAddress.Addr().String() + "/32"}, "port": strconv.Itoa(int(originAddress.Port()))}},
		}}},
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
			for key, expected := range xhttpHeaderData() {
				if r.Header.Get(key) != expected {
					observations.fail(fmt.Errorf("%s caller header data changed: %s", role, key))
					http.Error(w, "fixture header mismatch", http.StatusBadRequest)
					return
				}
			}
			observations.record(role + " " + r.Method)
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"+role+"/"), "/")
			observations.record(fmt.Sprintf("%s session=%x", role, sha256.Sum256([]byte(parts[0]))))
			if role == "upload" {
				seq := int64(-1)
				if len(parts) > 1 {
					if value, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						seq = value
					}
				}
				observations.record(fmt.Sprintf("upload seq=%d content-length=%d", seq, r.ContentLength))
				r.Body = &xhttpObservedBody{ReadCloser: r.Body, observe: func(stage string, count int64, err error) {
					observations.record(fmt.Sprintf("upload-body seq=%d stage=%s consumed=%d error-class=%T", seq, stage, count, err))
				}}
			}
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
	for modeIndex, mode := range []struct{ chained, independent bool }{{}, {chained: true}, {independent: true}} {
		chained := mode.chained
		name := fmt.Sprintf("caller_chain_%t", chained)
		if mode.independent {
			name = "independent_download"
		}
		passed := t.Run(name, func(t *testing.T) {
			dormantTLS := func() map[string]any {
				return map[string]any{"serverName": "dormant.invalid",
					"masterKeyLog":  "",
					"echConfigList": fmt.Sprintf("h2c://127.0.0.1:%d/ech-must-not-run", originAddress.Port())}
			}
			options := map[string]any{"penetrate": !mode.independent, "tcpKeepAliveIdle": 30, "addressPortStrategy": ""}
			if chained {
				options["dialerProxy"] = "caller-loop"
				options["addressPortStrategy"] = "NoNe"
			}
			download := map[string]any{"address": "endpoint.invalid", "port": downloadPort, "network": "xhttp",
				"sockopt":       map[string]any{"dialerProxy": "dormant-download-handler", "tcpKeepAliveIdle": 7, "addressPortStrategy": "srvportonly"},
				"xhttpSettings": map[string]any{"path": "/download", "host": "download.invalid", "headers": xhttpHeaderData()}}
			if mode.independent {
				download["sockopt"] = map[string]any{"tcpKeepAliveIdle": 7}
				download["xhttpSettings"].(map[string]any)["downloadSettings"] = map[string]any{"address": "127.0.0.1", "port": 9, "network": "tcp",
					"sockopt": map[string]any{"dialerProxy": "missing-grandchild"}}
			}
			download["security"], download["tlsSettings"] = "none", dormantTLS()
			outbounds := []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"address": "endpoint.invalid", "port": uploadPort, "id": identity, "encryption": "none"},
				"streamSettings": map[string]any{"network": "xhttp", "sockopt": options, "xhttpSettings": map[string]any{
					"path": "/upload", "host": "upload.invalid", "mode": "packet-up", "headers": map[string]string{"network": "dormant-outer-header"},
					"extra": map[string]any{"headers": xhttpHeaderData(), "downloadSettings": download}}}},
				map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}
			if chained {
				outbounds = append(outbounds, map[string]any{"tag": "carrier", "protocol": "socks", "settings": map[string]any{"address": "endpoint.invalid", "port": carrierPort}})
				outbounds = append(outbounds, map[string]any{"tag": "caller-loop", "protocol": "loopback",
					"settings":       map[string]any{"inboundTag": "caller-chain-scope"},
					"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "dormant-loop-handler"}}})
			}
			parentStream := outbounds[0].(map[string]any)["streamSettings"].(map[string]any)
			parentStream["security"], parentStream["tlsSettings"] = "none", dormantTLS()
			source := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{}, "outbounds": outbounds,
				"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.2"}, "queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}}}
			if chained {
				source["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{
					"type": "field", "inboundTag": []string{"caller-chain-scope"}, "outboundTag": "carrier"}}}
			}
			wantDownload, _ := json.Marshal(download)
			var prepared []byte
			var managedPort int
			if chained {
				// Freeze typed addresses before crossing into the client process.
				// Changing that process's environment must not retarget the session.
				const variable = "FLUTTER_VLESS_FIXTURE_ENDPOINT"
				t.Setenv(variable, "endpoint.invalid")
				control, _ := json.Marshal(source)
				for _, index := range []int{0, len(outbounds) - 2} {
					outbounds[index].(map[string]any)["settings"].(map[string]any)["address"] = "env:" + variable
				}
				download["address"] = "env:" + variable
				input, _ := json.Marshal(source)
				baseline := prepareEndpointAddress(t, control)
				effective := prepareEndpointAddress(t, input)
				if !reflect.DeepEqual(baseline, effective) {
					t.Fatal("environment XHTTP differs from its literal prepared control")
				}
				prepared, err = json.Marshal(effective)
				if err != nil {
					t.Fatal(err)
				}
				managedPort = int(effective["inbounds"].([]any)[0].(map[string]any)["port"].(float64))
				t.Setenv(variable, "unreachable.invalid")
			} else {
				prepared, managedPort = prepare(t, source)
			}
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			stream := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
			if stream["security"] != "none" || !reflect.DeepEqual(stream["tlsSettings"], parentStream["tlsSettings"]) {
				t.Fatal("XHTTP caller dormant parent TLS subtree changed")
			}
			if stream["sockopt"].(map[string]any)["addressPortStrategy"] != options["addressPortStrategy"] {
				t.Fatal("XHTTP preparation rewrote the caller's None strategy spelling")
			}
			actualDownload := stream["xhttpSettings"].(map[string]any)["extra"].(map[string]any)["downloadSettings"]
			got, _ := json.Marshal(actualDownload)
			if mode.independent {
				actualChild := actualDownload.(map[string]any)
				wantFields, actualFields := map[string]any{}, map[string]any{}
				for key, value := range download {
					if key != "sockopt" {
						wantFields[key] = value
					}
				}
				for key, value := range actualChild {
					if key != "sockopt" {
						actualFields[key] = value
					}
				}
				want, _ := json.Marshal(wantFields)
				actual, _ := json.Marshal(actualFields)
				childOptions := actualChild["sockopt"].(map[string]any)
				childScope, _ := childOptions["dialerProxy"].(string)
				if !bytes.Equal(want, actual) || childOptions["tcpKeepAliveIdle"] != float64(7) || childOptions["domainStrategy"] != "AsIs" ||
					childScope == "" || childScope == stream["sockopt"].(map[string]any)["dialerProxy"] {
					t.Fatal("independent child lost its own policy, private scope or inactive grandchild")
				}
			} else if !bytes.Equal(wantDownload, got) {
				t.Fatal("XHTTP preparation rewrote the inherited download stream")
			}
			if chained && stream["sockopt"].(map[string]any)["dialerProxy"] != "caller-loop" {
				t.Fatal("XHTTP parent caller chain changed")
			}
			if chained {
				var loop, carrier map[string]any
				for _, raw := range effective["outbounds"].([]any) {
					outbound := raw.(map[string]any)
					switch outbound["tag"] {
					case "caller-loop":
						loop = outbound
					case "carrier":
						carrier = outbound
					}
				}
				if loop == nil || carrier == nil || loop["protocol"] != "loopback" ||
					loop["settings"].(map[string]any)["inboundTag"] != "caller-chain-scope" ||
					loop["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"] != "dormant-loop-handler" {
					t.Fatal("caller loopback or its dormant sender changed")
				}
				foundRule := false
				for _, raw := range effective["routing"].(map[string]any)["rules"].([]any) {
					rule := raw.(map[string]any)
					if reflect.DeepEqual(rule["inboundTag"], []any{"caller-chain-scope"}) && rule["outboundTag"] == "carrier" {
						foundRule = true
					}
				}
				if !foundRule {
					t.Fatal("caller loopback no longer redispatches to the exact SOCKS carrier")
				}
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
					len(events), events[:min(len(events), 48)], failures[:min(len(failures), 8)], output)
			}
			if echRequests.Load() != 0 || originConnections.Load() != int64(modeIndex+1) {
				t.Fatal("dormant ECH did not stay inactive during exact payload", echRequests.Load(), originConnections.Load())
			}
			markerMode := "direct"
			if mode.independent {
				markerMode = "independent"
			} else if chained {
				markerMode = "chained"
			}
			t.Logf("XHTTP_DORMANT_ECH_PASS mode=%s", markerMode)
			if mode.independent {
				t.Log("XHTTP_INDEPENDENT_DOWNLOAD_PASS")
			} else {
				t.Logf("XHTTP_PENETRATE_PAYLOAD_PASS chained=%t bytes=%d", chained, len(payload))
				t.Logf("TRANSPORT_NONE_XHTTP_PAYLOAD_PASS chained=%t", chained)
				t.Logf("XHTTP_TRANSPORT_DATA_MAPS_PASS chained=%t", chained)
				if chained {
					t.Log("XHTTP_ENVIRONMENT_FROZEN_PASS")
					t.Log("XHTTP_LOOPBACK_CHAIN_PASS")
				}
			}
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
