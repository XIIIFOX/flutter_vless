//go:build flutter_vless_core31_followups

package http_test

// Exercise the actual Core HTTP inbound, not only its response parsing helper.
import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

type core31ContinueOrigin struct {
	listener net.Listener
	mu       sync.Mutex
	conn     net.Conn
	done     chan error
	stop     chan struct{}
	once     sync.Once
}

func (o *core31ContinueOrigin) close(t *testing.T) {
	t.Helper()
	o.once.Do(func() {
		close(o.stop)
		_ = o.listener.Close()
		o.mu.Lock()
		if o.conn != nil {
			_ = o.conn.Close()
		}
		o.mu.Unlock()
	})
	select {
	case <-o.done:
	case <-time.After(time.Second):
		t.Error("owned HTTP continue origin worker did not drain")
	}
}

func core31HTTPProxy(t *testing.T) (string, *core.Instance) {
	t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}}],"outbounds":[{"protocol":"freedom","settings":{}}]}`, port)
	config, err := serial.DecodeJSONConfig(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		result := make(chan error, 1)
		go func() { result <- instance.Close() }()
		select {
		case err := <-result:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Core HTTP inbound close exceeded deadline")
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("127.0.0.1:%d", port), instance
}

func core31StartContinueOrigin(t *testing.T, mode string, payload, response []byte) *core31ContinueOrigin {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &core31ContinueOrigin{listener: listener, done: make(chan error, 1), stop: make(chan struct{})}
	t.Cleanup(func() { o.close(t) })
	go func() {
		var result error
		defer func() { o.done <- result; close(o.done) }()
		conn, err := listener.Accept()
		if err != nil {
			result = err
			return
		}
		o.mu.Lock()
		o.conn = conn
		o.mu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			result = err
			return
		}
		// Closing an unread HTTP request body may drain it. Close the owned
		// socket first so 417/truncated controls cannot wait for an upload
		// which the client correctly never sends.
		defer func() { _ = conn.Close(); _ = request.Body.Close() }()
		if request.Method != http.MethodPost || request.URL.Path != "/owned-upload" || request.Header.Get("Expect") != "100-continue" || request.ContentLength != int64(len(payload)) {
			result = fmt.Errorf("origin request identity changed")
			return
		}
		switch mode {
		case "rejected_expectation":
			_, result = io.WriteString(conn, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		case "truncated_interim":
			_, result = io.WriteString(conn, "HTTP/1.1 100 Contin")
			return
		case "cancelled_origin":
			if _, err := io.WriteString(conn, "HTTP/1.1 100"); err != nil {
				result = err
				return
			}
			<-o.stop
			return
		}
		interim := []byte("HTTP/1.1 100 Continue\r\n\r\n")
		if mode == "fragmented_continue" {
			for _, b := range interim {
				if _, err := conn.Write([]byte{b}); err != nil {
					result = err
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		} else if _, err := conn.Write(interim); err != nil {
			result = err
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, int64(len(payload)+1)))
		if err != nil {
			result = err
			return
		}
		if !bytes.Equal(body, payload) {
			result = fmt.Errorf("origin upload bytes changed")
			return
		}
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(response)); err != nil {
			result = err
			return
		}
		_, result = conn.Write(response)
	}()
	return o
}

func TestCore31HTTPContinueUpload(t *testing.T) {
	if os.Getenv("CI") != "true" || runtime.GOOS == "darwin" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("Core31 native HTTP execution is CI-only")
	}
	for _, mode := range []string{"short_continue", "fragmented_continue", "rejected_expectation", "truncated_interim", "cancelled_origin"} {
		t.Run(mode, func(t *testing.T) {
			payload := make([]byte, 64*1024)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(payload)
			response := []byte("accepted:" + hex.EncodeToString(digest[:]))
			origin := core31StartContinueOrigin(t, mode, payload, response)
			address, _ := core31HTTPProxy(t)
			client, err := net.DialTimeout("tcp4", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := fmt.Fprintf(client, "POST http://%s/owned-upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", origin.listener.Addr(), origin.listener.Addr(), len(payload)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(client)
			request, _ := http.NewRequest(http.MethodPost, "http://"+origin.listener.Addr().String()+"/owned-upload", nil)
			if mode == "cancelled_origin" {
				_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				_, err := http.ReadResponse(reader, request)
				if err == nil {
					t.Fatal("stalled origin produced a successful HTTP response")
				}
				var netError net.Error
				if !errors.As(err, &netError) || !netError.Timeout() {
					t.Fatal("stalled origin did not reach the bounded read deadline", err)
				}
				_ = client.Close()
				origin.close(t)
				t.Log("CORE31_HTTP_CONTINUE_PASS mode=cancelled_origin body_sent=false deadline=true")
				return
			}
			first, err := http.ReadResponse(reader, request)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Body.Close()
			if mode == "rejected_expectation" || mode == "truncated_interim" {
				wanted := 417
				if mode == "truncated_interim" {
					wanted = 503
				}
				if first.StatusCode != wanted {
					t.Fatal("negative origin response was admitted", first.StatusCode, "want", wanted)
				}
				if _, err := io.Copy(io.Discard, first.Body); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-origin.done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("origin rejection worker did not drain")
				}
				t.Logf("CORE31_HTTP_CONTINUE_PASS mode=%s body_sent=false status=%d", mode, first.StatusCode)
				return
			}
			if first.StatusCode != 100 {
				t.Fatal("short interim 100 was not forwarded before upload", first.StatusCode)
			}
			// No upload byte is sent until the actual 23-byte interim response
			// crosses the Core inbound. The old Peek(56) would deadlock here.
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			final, err := http.ReadResponse(reader, request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(final.Body, 1024))
			closeErr := final.Body.Close()
			if readErr != nil || closeErr != nil || final.StatusCode != 200 || !bytes.Equal(body, response) {
				t.Fatal("final upload response changed", readErr, closeErr, final.StatusCode)
			}
			select {
			case err := <-origin.done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("origin upload witness did not drain")
			}
			t.Logf("CORE31_HTTP_CONTINUE_PASS mode=%s interim=100 final=200 bytes=%d", mode, len(payload))
		})
	}
}
