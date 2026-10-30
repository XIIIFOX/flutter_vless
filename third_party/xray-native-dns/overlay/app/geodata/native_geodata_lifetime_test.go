package geodata

// Real tiny loopback HTTPS/HTTP2 streams and real filesystem transactions.
// No external services, large assets, native resolver or VPN are exercised.
import (
	"bytes"
	"context"
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

type nativeGeodataTransport struct {
	*http2.Transport
	closed atomic.Int64
}

func (t *nativeGeodataTransport) CloseIdleConnections() {
	t.closed.Add(1)
	t.Transport.CloseIdleConnections()
}

func TestNativeGeoDataCloseCancelsNonIdleScheduledDownload(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("xray.location.asset", directory)
	target := filepath.Join(directory, "custom.dat")
	original := []byte{0x0a, 0x03, 0x0a, 0x01, 'A'}
	if err := os.WriteFile(target, original, 0600); err != nil { t.Fatal(err) }
	entered, handlerDone := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var active atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		defer close(handlerDone)
		if r.ProtoMajor != 2 { t.Errorf("expected actual HTTP/2, got %s", r.Proto) }
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flush := w.(http.Flusher)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := w.Write([]byte("tiny-non-idle-body")); err != nil { return }
			flush.Flush()
			once.Do(func() { close(entered) })
			select { case <-r.Context().Done(): return; case <-ticker.C: }
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	defer server.Close()
	defer server.CloseClientConnections()
	instance, err := core.New(&core.Config{})
	if err != nil { t.Fatal(err) }
	defer instance.Close()
	ctx := context.WithValue(parent, core.XrayKey(1), instance)
	g, err := New(ctx, &Config{Cron: "@every 1m", Assets: []*Asset{{Url: server.URL, File: "custom.dat"}}})
	if err != nil { t.Fatal(err) }
	transport := &nativeGeodataTransport{Transport: &http2.Transport{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}}
	defer transport.CloseIdleConnections()
	g.downloader.httpsClient = &http.Client{Transport: transport}
	// Accelerate the scheduler clock only; downloader/HTTP2/body/tempfiles/Close
	// are the actual implementation, and New still validates a one-minute cron.
	g.tasker = cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DiscardLogger)))
	if _, err := g.tasker.AddFunc("@every 1s", g.execute); err != nil { t.Fatal(err) }
	if err := g.Start(); err != nil { t.Fatal(err) }
	select { case <-entered: case <-time.After(3*time.Second): cancelParent(); _ = g.Close(); t.Fatal("scheduled loopback stream did not start") }
	staged, err := filepath.Glob(filepath.Join(directory, ".custom.dat.*.tmp"))
	if err != nil || len(staged) != 1 { cancelParent(); _ = g.Close(); t.Fatalf("download not staged: %v, %v", staged, err) }
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- g.Close() }()
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
	case <-time.After(2*time.Second):
		// Bounded RED cleanup: force only this test's request/socket, then join
		// Close instead of leaving a failing test's scheduler or goroutine alive.
		cancelParent()
		server.CloseClientConnections()
		select { case <-done: case <-time.After(2*time.Second): t.Fatal("Close did not join after forced test cleanup") }
		t.Fatal("GeoDAT Close waited on a non-idle download instead of cancelling its owned request")
	}
	if time.Since(started) >= 2*time.Second { t.Fatal("Close exceeded bounded stop budget") }
	if parent.Err() != nil { t.Fatal("Close cancelled caller/Core parent context") }
	select { case <-handlerDone: case <-time.After(time.Second): t.Fatal("loopback handler left alive") }
	if active.Load() != 0 { t.Fatal("active helper remains") }
	if transport.closed.Load() < 1 { t.Fatal("owned HTTP2 idle pool not closed") }
	if data, err := os.ReadFile(target); err != nil || !bytes.Equal(data, original) { t.Fatalf("cancelled update changed caller asset: %v", err) }
	for _, pattern := range []string{".custom.dat.*.tmp", ".custom.dat.*.bak"} {
		files, _ := filepath.Glob(filepath.Join(directory, pattern))
		if len(files) != 0 { t.Fatalf("owned staging left after Stop: %v", files) }
	}
	if err := g.Close(); err != nil { t.Fatal("repeated Close must stay safe") }
}

func TestNativeGeoDataSwapFailureRestoresEveryOriginalAndCleansBackups(t *testing.T) {
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one.dat"), filepath.Join(dir, "two.dat")
	for _, path := range []string{one, two} { if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) } }
	temp := filepath.Join(dir, ".one.dat.fixture.tmp")
	if err := os.WriteFile(temp, []byte("replacement"), 0600); err != nil { t.Fatal(err) }
	staged := []stage{{target: one, temp: temp}, {target: two, temp: filepath.Join(dir, "missing-stage")}}
	defer clean(staged)
	if _, err := swapAll(staged); err == nil { t.Fatal("missing second stage must fail transaction") }
	for _, path := range []string{one, two} { data, err := os.ReadFile(path); if err != nil || string(data) != "original" { t.Fatalf("partial update escaped rollback: %s: %v", filepath.Base(path), err) } }
	backups, _ := filepath.Glob(filepath.Join(dir, ".*.bak"))
	if len(backups) != 0 { t.Fatalf("owned backups left: %v", backups) }
}

func TestNativeGeoDataAssetCountAndOversizeMetadataRejectBeforeReplacement(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	target := filepath.Join(dir, "custom.DAT")
	if err := os.WriteFile(target, []byte("caller-full-dataset"), 0600); err != nil { t.Fatal(err) }
	instance, err := core.New(&core.Config{})
	if err != nil { t.Fatal(err) }
	defer instance.Close()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := context.WithValue(parent, core.XrayKey(1), instance)
	assets := make([]*Asset, 100)
	for index := range assets { assets[index] = &Asset{Url: "https://example.test/full.dat", File: "custom.DAT"} }
	g, err := New(ctx, &Config{Cron: "@daily", Assets: assets})
	if err != nil { t.Fatalf("100 custom DAT assets rejected: %v", err) }
	if err := g.Close(); err != nil { t.Fatal(err) }
	if parent.Err() != nil { t.Fatal("unstarted Close cancelled parent") }
	if _, err := New(ctx, &Config{Cron: "@daily", Assets: append(assets, assets[0])}); err == nil || !strings.Contains(err.Error(), "at most 100") { t.Fatal("101 assets not rejected") }
	// Test the real256MiB response-header guard with zero downloaded body;
	// never allocate, write or transfer a giant test dataset.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(maxDownloadSize+1, 10))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	d := &downloader{ctx: context.Background(), httpsClient: server.Client()}
	defer d.httpsClient.CloseIdleConnections()
	if _, err := d.downloadOne(&Asset{Url: server.URL, File: "custom.DAT"}); err == nil || !strings.Contains(err.Error(), "256 MiB") { t.Fatal("oversize metadata not rejected") }
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "caller-full-dataset" { t.Fatal("oversize response changed caller DAT") }
	files, _ := filepath.Glob(filepath.Join(dir, ".custom.DAT.*"))
	if len(files) != 0 { t.Fatal("oversize metadata left owned staging") }
}
