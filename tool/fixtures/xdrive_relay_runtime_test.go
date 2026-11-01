package xdrive_relay_runtime_test

// Two actual ordinary-Core instances exchange application bytes through a
// separately implemented, authenticated loopback S3 API. This is a complete
// local XDRIVE relay path, not a cloud-account or native OS VPN qualification.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const relayUser = "00000000-0000-4000-8000-000000000071"

func relayKeyPair(t *testing.T) (decryption, encryption string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes()),
		"mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// The published templates themselves must build under Core's complete XDRIVE
// validation. Their storage preparation tests alone cannot prove that contract.
func TestAcceptanceXdriveExampleContracts(t *testing.T) {
	_, encryption := relayKeyPair(t)
	values := map[string]string{"XDRIVE_VLESS_UUID": relayUser, "XDRIVE_VLESS_ENCRYPTION": encryption,
		"XDRIVE_S3_HOST": "s3.fixture.invalid", "XDRIVE_S3_REGION": "us-east-1", "XDRIVE_S3_BUCKET": "fixture-bucket", "XDRIVE_S3_PREFIX": "acceptance",
		"XDRIVE_S3_ACCESS_KEY_ID": "synthetic-access", "XDRIVE_S3_SECRET_ACCESS_KEY": "synthetic-secret",
		"XDRIVE_GOOGLE_FOLDER_ID": "synthetic-folder", "XDRIVE_GOOGLE_CLIENT_ID": "synthetic-client", "XDRIVE_GOOGLE_CLIENT_SECRET": "synthetic-secret", "XDRIVE_GOOGLE_REFRESH_TOKEN": "synthetic-refresh"}
	for _, name := range []string{"s3.json", "google-drive.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("native_xdrive_relay_runtime", "testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			rendered := string(data)
			for key, value := range values {
				rendered = strings.ReplaceAll(rendered, "${"+key+"}", value)
			}
			if strings.Contains(rendered, "${") {
				t.Fatal("unrecognized example placeholder")
			}
			if _, err := core.LoadConfig("json", strings.NewReader(rendered)); err != nil {
				t.Fatal("documented XDRIVE template rejected by actual Core", err)
			}
			for _, invalid := range []string{"missing-encryption", "missing-mux", "vision-flow", "negative-mux"} {
				t.Run(invalid, func(t *testing.T) {
					var document map[string]any
					if err := json.Unmarshal([]byte(rendered), &document); err != nil {
						t.Fatal(err)
					}
					outbound := document["outbounds"].([]any)[0].(map[string]any)
					settings := outbound["settings"].(map[string]any)
					want := "\"mux\""
					switch invalid {
					case "missing-encryption":
						settings["encryption"] = "none"
						want = "\"encryption\""
					case "missing-mux":
						delete(outbound, "mux")
					case "vision-flow":
						settings["flow"] = "xtls-rprx-vision"
						want = "\"flow\""
					case "negative-mux":
						outbound["mux"].(map[string]any)["concurrency"] = -1
					}
					encoded, _ := json.Marshal(document)
					if _, err := core.LoadConfig("json", bytes.NewReader(encoded)); err == nil || !strings.Contains(err.Error(), "xdrive transport") || !strings.Contains(err.Error(), want) {
						t.Fatal("invalid XDRIVE example escaped its specific Core constraint", invalid, err)
					}
				})
			}
		})
	}
}

func TestAcceptanceXdriveS3FullCoreRelay(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("actual XDRIVE Core relay is CI-only")
	}
	endpoint, err := url.Parse(os.Getenv("FLUTTER_VLESS_XDRIVE_FIXTURE_URL"))
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Path != "" {
		t.Fatal("independent numeric loopback S3 fixture required")
	}
	var resolverCalls atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		resolverCalls.Add(1)
		return nil, errors.New("XDRIVE relay fixture forbids OS DNS")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if resolverCalls.Load() != 0 {
			t.Error("numeric XDRIVE relay attempted OS DNS")
		}
	})
	for generation := 0; generation < 2; generation++ {
		t.Run("fresh-owner-"+strconv.Itoa(generation), func(t *testing.T) {
			var random [16]byte
			if _, err := rand.Read(random[:]); err != nil {
				t.Fatal(err)
			}
			nonce := hex.EncodeToString(random[:])
			decryption, encryption := relayKeyPair(t)
			payload := bytes.Repeat([]byte(nonce+"/binary\x00\xff/"), 1024)
			var originRequests atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
				if err != nil || r.Method != "POST" || r.URL.Path != "/"+nonce || !bytes.Equal(body, payload) {
					http.Error(w, "wrong synthetic relay request", http.StatusBadRequest)
					return
				}
				originRequests.Add(1)
				_, _ = w.Write(append([]byte("xdrive-relay|"), payload...))
			}))
			t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
			stream := map[string]any{"network": "xdrive", "security": "none", "xdriveSettings": map[string]any{
				"service": "s3", "remoteFolder": "acceptance/" + nonce,
				"secrets":      []string{"synthetic-xdrive-access", "synthetic-xdrive-secret"},
				"s3":           map[string]any{"endpoint": endpoint.String(), "region": "us-east-1", "bucket": "synthetic-xdrive-bucket", "pathStyle": true},
				"segmentBytes": 4096, "flushIntervalMs": 5, "pollIntervalMs": 5, "maxPollIntervalMs": 20,
				"eagerWindowMs": 100, "holeTimeoutMs": 3000, "sessionTtlSeconds": 60, "concurrency": 2,
			}}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			startCore := func(document map[string]any) (*core.Instance, func()) {
				t.Helper()
				encoded, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				compiled, err := core.LoadConfig("json", bytes.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				engine, err := core.NewWithContext(parent, compiled)
				if err != nil {
					t.Fatal(err)
				}
				var once sync.Once
				closeCore := func() {
					once.Do(func() {
						done := make(chan error, 1)
						go func() { done <- engine.Close() }()
						select {
						case err := <-done:
							if err != nil {
								t.Error("XDRIVE Core.Close failed", err)
							}
						case <-time.After(3 * time.Second):
							t.Error("XDRIVE Core.Close did not retire within its budget")
						}
					})
				}
				t.Cleanup(closeCore)
				if err := engine.Start(); err != nil {
					t.Fatal(err)
				}
				return engine, closeCore
			}
			server, closeServer := startCore(map[string]any{"log": map[string]any{"loglevel": "none"},
				"inbounds": []any{map[string]any{"protocol": "vless", "tag": "cloud-server", "listen": "127.0.0.1", "port": 18771,
					"settings": map[string]any{"decryption": decryption, "clients": []any{map[string]any{"id": relayUser}}}, "streamSettings": stream}},
				"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}, map[string]any{"action": "block"}}}}}})
			_ = server
			client, closeClient := startCore(map[string]any{"log": map[string]any{"loglevel": "none"},
				"outbounds": []any{map[string]any{"protocol": "vless", "tag": "cloud-client", "settings": map[string]any{
					"vnext": []any{map[string]any{"address": "127.0.0.1", "port": 18771, "users": []any{map[string]any{"id": relayUser, "encryption": encryption}}}}},
					"mux": map[string]any{"enabled": true, "concurrency": 1, "xudpConcurrency": 1, "xudpProxyUDP443": "allow"}, "streamSettings": stream}}})
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				host, portText, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				port, err := strconv.Atoi(portText)
				if err != nil {
					return nil, err
				}
				return core.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
			}}
			defer transport.CloseIdleConnections()
			requestClient := &http.Client{Transport: transport, Timeout: 12 * time.Second}
			response, err := requestClient.Post(origin.URL+"/"+nonce, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal("full S3 cloud relay request failed", err)
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+128)))
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 || !bytes.Equal(body, append([]byte("xdrive-relay|"), payload...)) || originRequests.Load() != 1 {
				t.Fatal("full S3 relay response/counter mismatch", err)
			}
			closeClient()
			closeServer()
			if parent.Err() != nil {
				t.Fatal("closing XDRIVE peers cancelled their caller context")
			}
			t.Log("full S3 relay: two actual Core owners; multi-segment application payload in both directions; caller context preserved; both owners closed")
		})
	}
}
