package websocket

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type lifetimeTestManager struct{ outbound.Manager }

func (lifetimeTestManager) GetHandler(tag string) outbound.Handler {
	if tag == "owned-test-relay" {
		return lifetimeTestRelay{}
	}
	return nil
}

type lifetimeTestRelay struct{ outbound.Handler }

func (lifetimeTestRelay) Dispatch(ctx context.Context, link *transport.Link) {
	defer common.Close(link.Writer)
	defer common.Interrupt(link.Reader)
	paths := session.OutboundsFromContext(ctx)
	dialer := &gonet.Dialer{Timeout: time.Second}
	peer, err := dialer.DialContext(ctx, "tcp", paths[len(paths)-1].Target.NetAddr())
	if err != nil {
		return
	}
	defer peer.Close()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		_ = buf.Copy(link.Reader, buf.NewWriter(peer))
		_ = peer.Close()
	}()
	_ = buf.Copy(buf.NewReader(peer), link.Writer)
	common.Interrupt(link.Reader)
	<-sent
}

func lifetimeTestSettings(t *testing.T, server *httptest.Server, fingerprint string) (net.Destination, *internet.MemoryStreamConfig) {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	settings := &internet.MemoryStreamConfig{
		ProtocolSettings: &Config{Path: "/echo", Host: serverURL.Host},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Fingerprint: fingerprint, ServerName: serverURL.Hostname(), DisableSystemRoot: true,
			Certificate: []*tls.Certificate{{Certificate: cert, Usage: tls.Certificate_AUTHORITY_VERIFY}},
		},
		SocketSettings: &internet.SocketConfig{DialerProxy: "owned-test-relay"},
	}
	return net.TCPDestination(net.LocalHostIP, net.Port(port)), settings
}

func TestNativeWebSocketHandshakeLifetime(t *testing.T) {
	internet.InitSystemDialer(nil, lifetimeTestManager{})
	t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })

	for _, fingerprint := range []string{"firefox", "unsafe"} {
		t.Run(fingerprint+"/successful_handoff", func(t *testing.T) {
			upgrader := websocket.Upgrader{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				kind, data, err := conn.ReadMessage()
				if err == nil {
					_ = conn.WriteMessage(kind, data)
				}
			}))
			defer server.Close()
			dest, settings := lifetimeTestSettings(t, server, fingerprint)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := Dial(ctx, dest, settings)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cancel()

			exchange := make(chan error, 1)
			go func() {
				if _, err := conn.Write([]byte("test")); err != nil {
					exchange <- err
					return
				}
				var result [4]byte
				_, err := io.ReadFull(conn, result[:])
				if err == nil && string(result[:]) != "test" {
					err = errors.New("echo differs")
				}
				exchange <- err
			}()
			select {
			case err := <-exchange:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				_ = conn.Close()
				<-exchange
				t.Fatal("live WebSocket stopped forwarding after handoff")
			}
		})

		t.Run(fingerprint+"/cancel_opening", func(t *testing.T) {
			arrived := make(chan struct{})
			stopped := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(arrived)
				<-r.Context().Done()
				close(stopped)
			}))
			defer server.Close()
			dest, settings := lifetimeTestSettings(t, server, fingerprint)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := Dial(ctx, dest, settings)
				if conn != nil {
					_ = conn.Close()
				}
				result <- err
			}()

			select {
			case <-arrived:
			case <-time.After(3 * time.Second):
				server.CloseClientConnections()
				t.Fatal("test Upgrade request did not arrive")
			}
			cancel()

			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("opening did not return cancellation: %v", err)
				}
			case <-time.After(2 * time.Second):
				server.CloseClientConnections()
				<-result
				t.Fatal("opening did not stop")
			}
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				server.CloseClientConnections()
				t.Fatal("peer continued waiting")
			}
		})
	}
}
