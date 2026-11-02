//go:build flutter_vless_core31_followups

package splithttp

// CI-only feature acceptance. These tests use the ordinary protected Core
// composition, not the optional strict native-DNS-context research overlay.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

func core31XHTTPGate(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "true" || runtime.GOOS == "darwin" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("Core31 native feature execution is CI-only")
	}
}

func core31XHTTPPort(t *testing.T) xnet.Port {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := xnet.Port(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func core31XHTTPKeys(t *testing.T) (*xtls.Config, *xtls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(31),
		Subject: pkix.Name{CommonName: "core31-xhttp.invalid"}, DNSNames: []string{"core31-xhttp.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	server := &xtls.Config{NextProtocol: []string{"h2"}, Certificate: []*xtls.Certificate{{Certificate: certPEM, Key: keyPEM}}}
	client := &xtls.Config{ServerName: "core31-xhttp.invalid", NextProtocol: []string{"h2"}, DisableSystemRoot: true,
		Certificate: []*xtls.Certificate{{Certificate: certPEM, Usage: xtls.Certificate_AUTHORITY_VERIFY}}}
	return server, client
}

type core31XHTTPObservedTransport struct {
	inner             http.RoundTripper
	mu                sync.Mutex
	uplink, preflight int
	method            string
	active            atomic.Int32
	responses         atomic.Int32
	invalidResponses  atomic.Int32
}

type core31XHTTPResponseBody struct {
	io.ReadCloser
	once   sync.Once
	active *atomic.Int32
}

func (b *core31XHTTPResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.active.Add(-1) })
	return err
}

func (r *core31XHTTPObservedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	if req.Method == r.method {
		r.uplink++
		if req.Header.Get("Access-Control-Request-Method") != "" {
			r.preflight++
		}
	}
	r.mu.Unlock()
	r.active.Add(1)
	response, err := r.inner.RoundTrip(req)
	if err != nil {
		r.active.Add(-1)
		return response, err
	}
	r.responses.Add(1)
	if response.ProtoMajor != 2 || response.StatusCode != 200 {
		r.invalidResponses.Add(1)
	}
	response.Body = &core31XHTTPResponseBody{ReadCloser: response.Body, active: &r.active}
	return response, nil
}

func core31CloseXHTTPClient(t *testing.T, destination xnet.Destination, settings *internet.MemoryStreamConfig, client *DefaultDialerClient, observed *core31XHTTPObservedTransport) {
	t.Helper()
	if transport, ok := observed.inner.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	_ = client.Close()
	deadline := time.Now().Add(time.Second)
	for observed.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if observed.active.Load() != 0 {
		t.Error("owned XHTTP response bodies did not drain")
	}
	// Own exactly the entry allocated for this unique test stream settings.
	globalDialerAccess.Lock()
	delete(globalDialerMap, dialerConf{destination, settings})
	globalDialerAccess.Unlock()
}

func TestCore31XHTTPOptions(t *testing.T) {
	core31XHTTPGate(t)
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		for _, method := range []string{"POST", "OPTIONS"} {
			t.Run(mode+"/"+method, func(t *testing.T) {
				payload := make([]byte, 4096)
				if _, err := rand.Read(payload); err != nil {
					t.Fatal(err)
				}
				response := append([]byte("core31-echo:"), payload...)
				serverTLS, clientTLS := core31XHTTPKeys(t)
				port := core31XHTTPPort(t)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				var active atomic.Int32
				serverResult := make(chan error, 1)
				listener, err := ListenXH(ctx, xnet.LocalHostIP, port, &internet.MemoryStreamConfig{
					ProtocolName: "splithttp", ProtocolSettings: &Config{Path: "/core31", Mode: mode},
					SecurityType: "tls", SecuritySettings: serverTLS,
				}, func(conn stat.Connection) {
					active.Add(1)
					go func() {
						defer active.Add(-1)
						defer conn.Close()
						body := make([]byte, len(payload))
						if _, err := io.ReadFull(conn, body); err != nil {
							serverResult <- err
							return
						}
						if !bytes.Equal(body, payload) {
							serverResult <- fmt.Errorf("origin upload bytes changed")
							return
						}
						_, err := conn.Write(response)
						serverResult <- err
					}()
				})
				if err != nil {
					t.Fatal(err)
				}
				ln := listener.(*Listener)
				t.Cleanup(func() {
					_ = ln.server.Close()
					_ = listener.Close()
					deadline := time.Now().Add(time.Second)
					for active.Load() != 0 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
					if active.Load() != 0 {
						t.Error("owned XHTTP echo worker did not drain")
					}
				})
				settings := &internet.MemoryStreamConfig{ProtocolName: "splithttp",
					ProtocolSettings: &Config{Path: "/core31", Mode: mode, UplinkHTTPMethod: method,
						Xmux: &XmuxConfig{MaxConnections: &RangeConfig{From: 1, To: 1}}},
					SecurityType: "tls", SecuritySettings: clientTLS}
				destination := xnet.TCPDestination(xnet.LocalHostIP, port)
				httpClient, _ := getHTTPClient(ctx, destination, settings)
				direct := httpClient.(*DefaultDialerClient)
				observed := &core31XHTTPObservedTransport{inner: direct.client.Transport, method: method}
				direct.client.Transport = observed
				// splitConn deadline methods are intentionally no-ops upstream.
				// Bound the real HTTP operations, not a cosmetic net.Conn deadline.
				direct.client.Timeout = 3 * time.Second
				t.Cleanup(func() { _ = ln.server.Close(); core31CloseXHTTPClient(t, destination, settings, direct, observed) })
				conn, err := Dial(ctx, destination, settings)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				result := make(chan error, 1)
				go func() {
					if _, err := conn.Write(payload); err != nil {
						result <- err
						return
					}
					got := make([]byte, len(response))
					if _, err := io.ReadFull(conn, got); err != nil {
						result <- err
						return
					}
					if !bytes.Equal(got, response) {
						result <- fmt.Errorf("downlink bytes changed")
						return
					}
					result <- nil
				}()
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					_ = conn.Close()
					_ = ln.server.Close()
					select {
					case <-result:
					case <-time.After(time.Second):
						t.Error("owned XHTTP client did not drain")
					}
					t.Fatal("XHTTP payload exchange exceeded deadline")
				}
				select {
				case err := <-serverResult:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("origin payload witness missing")
				}
				observed.mu.Lock()
				uplink, preflight := observed.uplink, observed.preflight
				observed.mu.Unlock()
				if uplink == 0 || preflight != 0 {
					t.Fatal("uplink method missing or mislabelled as CORS preflight")
				}
				if observed.responses.Load() == 0 || observed.invalidResponses.Load() != 0 {
					t.Fatal("XHTTP did not complete valid HTTP/2 responses")
				}
				t.Logf("CORE31_XHTTP_OPTIONS_PASS mode=%s method=%s bytes=%d", mode, method, len(payload))
			})
		}
	}
}

func core31ReadH2Settings(t *testing.T, addr string) map[http2.SettingID]uint32 {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
			values := map[http2.SettingID]uint32{}
			if err := settings.ForeachSetting(func(setting http2.Setting) error { values[setting.ID] = setting.Val; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := framer.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
			return values
		}
	}
	t.Fatal("server did not send initial HTTP/2 SETTINGS")
	return nil
}

func TestCore31XHTTPH2ParamsWire(t *testing.T) {
	core31XHTTPGate(t)
	for _, mode := range []string{"baseline", "custom"} {
		t.Run(mode, func(t *testing.T) {
			config := &Config{Path: "/core31", Mode: "packet-up"}
			if mode == "custom" {
				config.H2Params = []byte(`{"MaxConcurrentStreams":7,"MaxReadFrameSize":32768}`)
			}
			var dispatched atomic.Int32
			listener, err := ListenXH(context.Background(), xnet.LocalHostIP, core31XHTTPPort(t),
				&internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: config},
				func(conn stat.Connection) { dispatched.Add(1); _ = conn.Close() })
			if err != nil {
				t.Fatal(err)
			}
			ln := listener.(*Listener)
			t.Cleanup(func() { _ = ln.server.Close(); _ = listener.Close() })
			addr := listener.Addr().String()
			settings := core31ReadH2Settings(t, addr)
			if mode == "custom" {
				if settings[http2.SettingMaxConcurrentStreams] != 7 || settings[http2.SettingMaxFrameSize] != 32768 {
					t.Fatal("h2Params did not reach the actual HTTP/2 SETTINGS frame", settings)
				}
			} else if settings[http2.SettingMaxConcurrentStreams] == 7 {
				t.Fatal("baseline accidentally uses the custom H2 limit")
			}
			transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, _, addr string, _ *gotls.Config) (net.Conn, error) {
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", addr)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			for _, requestMode := range []string{"preflight", "wrong_path"} {
				path := "/core31/"
				if requestMode == "wrong_path" {
					path = "/unrelated/"
				}
				req, err := http.NewRequest(http.MethodOptions, "http://"+addr+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Origin", "https://owned-client.invalid")
				req.Header.Set("Access-Control-Request-Method", "OPTIONS")
				req.Header.Set("Access-Control-Request-Headers", "x-owned-nonce")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				if response.ProtoMajor != 2 {
					t.Fatal("actual request did not use HTTP/2")
				}
				if requestMode == "preflight" {
					if response.StatusCode != 200 || len(body) != 0 || response.Header.Get("Access-Control-Allow-Methods") != "OPTIONS" || response.Header.Get("Access-Control-Allow-Origin") != "https://owned-client.invalid" || response.Header.Get("Access-Control-Allow-Headers") != "x-owned-nonce" {
						t.Fatal("genuine CORS preflight response changed", response.StatusCode, response.Header)
					}
				} else if response.StatusCode != 404 {
					t.Fatal("wrong-path negative control admitted", response.StatusCode)
				}
			}
			if dispatched.Load() != 0 {
				t.Fatal("CORS preflight/wrong path dispatched an application stream")
			}
			t.Logf("CORE31_XHTTP_H2_PARAMS_PASS mode=%s settings=true preflight=true wrong_path=true", mode)
		})
	}
}
