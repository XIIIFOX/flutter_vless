//go:build flutter_vless_core31_followups

package geodata

// Exercise the pinned downloader, real HTTP/2 streams and actual stage/swap
// files. Payloads are tiny synthetic byte fixtures, not replacement GeoDATs.
// The decoded-size test streams the actual 256 MiB boundary into a counting
// sink: no 256 MiB allocation or temporary asset is created for that case.
import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/xtls/xray-core/core"
	"golang.org/x/net/http2"
)

func nativeGeoGzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	if _, err := z.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func nativeGeoGzipServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("gzip fixture requires actual HTTP/2, got %s", r.Proto)
		}
		handler(w, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	server.Client().Timeout = 20 * time.Second
	t.Cleanup(func() { server.Client().CloseIdleConnections(); server.CloseClientConnections(); server.Close() })
	return server
}

func nativeGeoGzipNoStaging(t *testing.T, directory string) {
	t.Helper()
	for _, pattern := range []string{".*.tmp", ".*.bak"} {
		files, err := filepath.Glob(filepath.Join(directory, pattern))
		if err != nil || len(files) != 0 {
			t.Fatalf("owned staging remains: %v, %v", files, err)
		}
	}
}

func TestNativeGeoDataGzipContentsAndCorruptPreservation(t *testing.T) {
	payload := []byte("finite GeoDAT downloader fixture\x00\xff\x01")
	valid := nativeGeoGzipBytes(t, payload)
	badCRC := append([]byte(nil), valid...)
	badCRC[len(badCRC)-8] ^= 0x80
	cases := []struct {
		name, path string
		body       []byte
		want       []byte
		wantError  string
	}{
		{"gzip_without_gz_extension", "/ordinary.dat", valid, payload, ""},
		{"raw_with_gz_extension", "/misleading.gz", payload, payload, ""},
		{"corrupt_header", "/ordinary.dat", []byte{0x1f, 0x8b, 0xff, 0, 0, 0, 0, 0, 0, 0}, nil, "gzip"},
		{"truncated_header", "/ordinary.dat", []byte{0x1f, 0x8b, 8}, nil, "unexpected EOF"},
		{"truncated_trailer", "/ordinary.dat", valid[:len(valid)-4], nil, "unexpected EOF"},
		{"corrupt_checksum", "/ordinary.dat", badCRC, nil, "invalid checksum"},
		{"empty_decoded_body", "/ordinary.dat", nativeGeoGzipBytes(t, nil), nil, "empty response body"},
		{"corrupt_second_member", "/ordinary.dat", append(append([]byte(nil), valid...), badCRC...), nil, "invalid checksum"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("xray.location.asset", directory)
			target := filepath.Join(directory, "custom.dat")
			original := []byte("caller original must survive failed gzip")
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			var served atomic.Int64
			server := nativeGeoGzipServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != c.path {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				// Deliberately omit Content-Encoding and use a non-gzip MIME type.
				// Detection must inspect the received bytes, not URL/header hints.
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", strconv.Itoa(len(c.body)))
				n, err := w.Write(c.body)
				if err != nil || n != len(c.body) {
					t.Errorf("fixture body write: %d, %v", n, err)
				}
				served.Add(1)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			d := &downloader{ctx: ctx, httpsClient: server.Client()}
			staged, err := d.downloadOne(&Asset{Url: server.URL + c.path, File: "custom.dat"})
			if c.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantError) {
					t.Fatalf("invalid compressed data accepted / unexpected error: %v", err)
				}
				if staged != (stage{}) {
					t.Fatal("failed compressed response escaped as a usable stage")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer clean([]stage{staged})
				data, err := os.ReadFile(staged.temp)
				want := append([]byte(luaGuardHeader), c.want...)
				if err != nil || !bytes.Equal(data, want) {
					t.Fatalf("exact decoded stage mismatch: %v", err)
				}
				unchanged, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(unchanged, original) {
					t.Fatal("fetch changed target before transaction")
				}
				tx, err := swapAll([]stage{staged})
				if err != nil {
					t.Fatal(err)
				}
				if err := tx.commit(); err != nil {
					t.Fatal(err)
				}
				data, err = os.ReadFile(target)
				if err != nil || !bytes.Equal(data, want) {
					t.Fatalf("committed decoded target mismatch: %v", err)
				}
			}
			if c.wantError != "" {
				data, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(data, original) {
					t.Fatal("failed gzip replaced caller bytes")
				}
			}
			if served.Load() != 1 {
				t.Fatal("fixture did not serve exactly one real request")
			}
			nativeGeoGzipNoStaging(t, directory)
			t.Logf("GEODAT_GZIP_CONTENT_PASS mode=%s", c.name)
		})
	}
}

type nativeGeoGzipZeros struct{}

func (nativeGeoGzipZeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type nativeGeoGzipZeroSink struct{ n int64 }

func (w *nativeGeoGzipZeroSink) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, fmt.Errorf("unexpected decoded payload byte")
		}
	}
	w.n += int64(len(p))
	if w.n > maxDownloadSize+1 {
		return 0, fmt.Errorf("decoder read beyond real cap+1")
	}
	return len(p), nil
}

func TestNativeGeoDataGzipDecodedLimit(t *testing.T) {
	if maxDownloadSize != 256*1024*1024 {
		t.Fatal("acceptance must exercise actual fixed 256 MiB production limit")
	}
	for _, c := range []struct {
		name     string
		size     int64
		rejected bool
	}{
		{"exact_256MiB", maxDownloadSize, false},
		{"over_256MiB", maxDownloadSize + 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var encoded bytes.Buffer
			z, err := gzip.NewWriterLevel(&encoded, gzip.BestSpeed)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := io.CopyN(z, nativeGeoGzipZeros{}, c.size); err != nil || n != c.size {
				t.Fatalf("bounded fixture compression: %d, %v", n, err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			if encoded.Len() > 2*1024*1024 {
				t.Fatal("fixture must stay small on the wire and in memory")
			}
			var served atomic.Int64
			server := nativeGeoGzipServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(encoded.Len()))
				n, err := w.Write(encoded.Bytes())
				if err != nil || n != encoded.Len() {
					t.Errorf("small compressed body write: %d, %v", n, err)
				}
				served.Add(1)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			d := &downloader{ctx: ctx, httpsClient: server.Client()}
			var sink nativeGeoGzipZeroSink
			err = d.fetch(server.URL+"/compressed.dat", &sink)
			if c.rejected {
				if err == nil || !strings.Contains(err.Error(), "exceeds 256 MiB") {
					t.Fatalf("decoded oversize accepted / wrong failure: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if sink.n != c.size {
				t.Fatalf("did not reach exact decoded-size boundary: %d", sink.n)
			}
			if served.Load() != 1 {
				t.Fatal("missing actual compressed HTTP/2 response")
			}
			t.Logf("GEODAT_GZIP_LIMIT_PASS mode=%s decoded=%d wire=%d", c.name, sink.n, encoded.Len())
		})
	}
}

func TestNativeGeoDataGzipBatchStagingAndCommit(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("xray.location.asset", directory)
	for _, name := range []string{"one.dat", "two.dat"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("old-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	one := nativeGeoGzipBytes(t, []byte("new-one"))
	two := nativeGeoGzipBytes(t, []byte("new-two"))
	var badSecond atomic.Bool
	badSecond.Store(true)
	server := nativeGeoGzipServer(t, func(w http.ResponseWriter, r *http.Request) {
		body := one
		if r.URL.Path == "/two" {
			body = two
			if badSecond.Load() {
				body = two[:len(two)-3]
			}
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("batch fixture write: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &downloader{ctx: ctx, httpsClient: server.Client()}
	assets := []*Asset{{Url: server.URL + "/one", File: "one.dat"}, {Url: server.URL + "/two", File: "two.dat"}}
	staged, err := d.download(assets)
	if err == nil || staged != nil {
		t.Fatal("corrupt second download must reject entire staged batch")
	}
	for _, name := range []string{"one.dat", "two.dat"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || string(data) != "old-"+name {
			t.Fatal("failed compressed batch changed an original")
		}
	}
	nativeGeoGzipNoStaging(t, directory)
	badSecond.Store(false)
	staged, err = d.download(assets)
	if err != nil || len(staged) != 2 {
		t.Fatalf("valid compressed batch: %v", err)
	}
	defer clean(staged)
	for _, name := range []string{"one.dat", "two.dat"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || string(data) != "old-"+name {
			t.Fatal("fetch committed before all assets were staged")
		}
	}
	tx, err := swapAll(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.commit(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, payload string }{{"one.dat", "new-one"}, {"two.dat", "new-two"}} {
		data, err := os.ReadFile(filepath.Join(directory, c.name))
		if err != nil || string(data) != luaGuardHeader+c.payload {
			t.Fatal("exact gzip batch commit failed")
		}
	}
	nativeGeoGzipNoStaging(t, directory)
	t.Log("GEODAT_GZIP_TRANSACTION_PASS")
}

type nativeGeoGzipTransport struct {
	*http2.Transport
	closed atomic.Int64
}

func (t *nativeGeoGzipTransport) CloseIdleConnections() {
	t.closed.Add(1)
	t.Transport.CloseIdleConnections()
}

func TestNativeGeoDataGzipCloseCancelsActiveCompressedDownload(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("xray.location.asset", directory)
	target := filepath.Join(directory, "custom.dat")
	original := []byte("original survives active gzip cancellation")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	entered, handlerDone := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var active atomic.Int64
	server := nativeGeoGzipServer(t, func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer func() {
			active.Add(-1)
			close(handlerDone)
		}()
		z := gzip.NewWriter(w)
		defer z.Close()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := z.Write([]byte("non-idle-compressed-update")); err != nil {
				return
			}
			if err := z.Flush(); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			once.Do(func() { close(entered) })
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
	parent, cancelParent := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelParent()
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx := context.WithValue(parent, core.XrayKey(1), instance)
	g, err := New(ctx, &Config{Cron: "@every 1m", Assets: []*Asset{{Url: server.URL + "/no-extension", File: "custom.dat"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	transport := &nativeGeoGzipTransport{Transport: &http2.Transport{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}}
	defer transport.CloseIdleConnections()
	g.downloader.httpsClient = &http.Client{Transport: transport, Timeout: 7 * time.Second}
	// Accelerate cron only, retaining actual downloader, gzip, files and Close.
	g.tasker = cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DiscardLogger)))
	if _, err := g.tasker.AddFunc("@every 1s", g.execute); err != nil {
		t.Fatal(err)
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		cancelParent()
		server.CloseClientConnections()
		t.Fatal("compressed scheduled download did not start")
	}
	files, err := filepath.Glob(filepath.Join(directory, ".custom.dat.*.tmp"))
	if err != nil || len(files) != 1 {
		cancelParent()
		server.CloseClientConnections()
		t.Fatalf("actual compressed download not staged: %v, %v", files, err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		cancelParent()
		server.CloseClientConnections()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("gzip Close did not join after forced fixture cleanup")
		}
		t.Fatal("GeoDAT Close waited for active compressed body instead of cancelling")
	}
	if parent.Err() != nil {
		t.Fatal("Close cancelled caller parent or exceeded fixture deadline")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("compressed helper handler not drained")
	}
	if active.Load() != 0 {
		t.Fatal("active compressed handler remains")
	}
	if transport.closed.Load() < 1 {
		t.Fatal("owned HTTP/2 pool not closed")
	}
	data, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("cancelled gzip changed caller asset")
	}
	nativeGeoGzipNoStaging(t, directory)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("GEODAT_GZIP_CANCEL_PASS")
}
