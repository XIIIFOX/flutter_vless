package xdrive

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// CI-only real loopback I/O; run on the ordinary patched Core copy, not the
// separately restricted native-DNS prototype. No cloud account is contacted.
func TestAcceptanceXdriveS3RequestsSigningFrontingAndClose(t *testing.T) {
	var mu sync.Mutex
	objects := make(map[string][]byte)
	started, drained, forced := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var startOnce, drainOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "storage-origin.invalid:8989" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=synthetic-access/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/base/synthetic-bucket/")
		if key == "synthetic-prefix/stream" && r.Method == "GET" {
			defer drainOnce.Do(func() { close(drained) })
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("progress"))
			w.(http.Flusher).Flush()
			startOnce.Do(func() { close(started) })
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-forced:
					return
				case <-ticker.C:
					if _, err := w.Write([]byte("progress")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Query().Get("list-type") == "2" {
			page := s3ListPage{}
			for key := range objects {
				if strings.HasPrefix(key, r.URL.Query().Get("prefix")) {
					page.Contents = append(page.Contents, struct{ Key string }{key})
				}
			}
			_ = xml.NewEncoder(w).Encode(page)
			return
		}
		switch r.Method {
		case "PUT":
			data, _ := io.ReadAll(r.Body)
			objects[key] = data
			w.WriteHeader(http.StatusOK)
		case "GET":
			if data, ok := objects[key]; ok {
				_, _ = w.Write(data)
			} else {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
			}
		case "DELETE":
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(func() { close(forced); server.CloseClientConnections(); server.Close() })
	address, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(address.Port())
	stream := nativeS3Stream()
	stream.ProtocolSettings.(*Config).S3.Endpoint = "http://storage-origin.invalid:8989/base"
	stream.Destination = &xnet.Destination{Address: xnet.LocalHostIP, Port: xnet.Port(port), Network: xnet.Network_TCP}
	ctx, owner := ContextWithNativeLifetime(context.Background())
	defer owner.Close()
	base, err := newNativeStorage(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	storage := sessionStorage(base)
	defer storage.Close()
	if err := storage.Put(ctx, "proof/payload", []byte("native-s3-proof")); err != nil {
		t.Fatal(err)
	}
	data, err := storage.Get(ctx, "proof/payload")
	if err != nil || string(data) != "native-s3-proof" {
		t.Fatal("S3 data mismatch", err)
	}
	entries, err := storage.List(ctx, "proof")
	if err != nil || len(entries) != 1 || entries[0].Name != "payload" {
		t.Fatal("S3 listing mismatch", err)
	}
	if err := storage.Delete(ctx, "proof/payload"); err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() { _, err := storage.Get(context.Background(), "stream"); requestDone <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("owned stream did not start")
	}
	owner.Close()
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("stream succeeded after owner cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("S3 request/retry loop survived Core ownership close")
	}
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("S3 server handler did not drain")
	}
	if len(owner.storage) != 0 {
		t.Fatal("closed owner retained cloud cache")
	}
}

func TestAcceptanceXdriveGoogleDriveRequestsAndFreshOwner(t *testing.T) {
	server := newFakeDrive(t) // pinned upstream's entirely local fake OAuth/files API.
	stream := nativeS3Stream()
	stream.ProtocolSettings = &Config{Service: "google-drive", RemoteFolder: "synthetic-folder",
		Secrets: []string{"synthetic-client", "synthetic-secret", "synthetic-refresh"}}
	for generation := 0; generation < 2; generation++ {
		ctx, owner := ContextWithNativeLifetime(context.Background())
		func() {
			defer owner.Close()
			base, err := newNativeStorage(ctx, stream)
			if err != nil {
				t.Fatal(err)
			}
			storage := sessionStorage(base)
			defer storage.Close()
			if err := storage.Put(ctx, "proof/payload", []byte("native-drive-proof")); err != nil {
				t.Fatal(err)
			}
			data, err := storage.Get(ctx, "proof/payload")
			if err != nil || string(data) != "native-drive-proof" {
				t.Fatal("Drive data mismatch", err)
			}
			entries, err := storage.List(ctx, "proof")
			if err != nil || len(entries) != 1 || entries[0].Name != "payload" {
				t.Fatal("Drive listing mismatch", err)
			}
			if err := storage.Delete(ctx, "proof/payload"); err != nil {
				t.Fatal(err)
			}
		}()
		if len(owner.storage) != 0 {
			t.Fatal("closed Drive cache retained")
		}
	}
	server.mu.Lock()
	tokens := server.tokens
	remaining := len(server.files)
	server.mu.Unlock()
	if tokens != 2 || remaining != 0 {
		t.Fatalf("restart reused token cache or remote fixture objects: tokens=%d files=%d", tokens, remaining)
	}
}
