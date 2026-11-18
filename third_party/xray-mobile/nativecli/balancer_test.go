package nativecli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type balancerTestBackend struct {
	configuration string
	checkedSpec   string
	inbound       string
	capacity      int64
	rows          string
	stopped       bool
}

func (*balancerTestBackend) Capability() int64 { return 1 }
func (b *balancerTestBackend) CheckRouting(_, spec []byte) int64 {
	b.checkedSpec = string(spec)
	return 0
}
func (b *balancerTestBackend) Start(config, _ []byte, inbound string, capacity int64) error {
	b.configuration, b.inbound, b.capacity = string(config), inbound, capacity
	b.rows = "4,1,2\n5,1,1\n"
	return nil
}
func (b *balancerTestBackend) Snapshot() string { return b.rows }
func (b *balancerTestBackend) Disable()         { b.rows = "" }
func (b *balancerTestBackend) Stop()            { b.stopped = true }

func TestBalancerCapabilityFrames(t *testing.T) {
	for _, tt := range []struct {
		backend BalancerBackend
		code    int
		frame   string
	}{
		{&balancerTestBackend{}, 0, `{"stage":"capabilities","code":0,"capability":1}`},
		{nil, 32, `{"stage":"capabilities","code":32,"capability":0}`},
	} {
		var output bytes.Buffer
		if code := RunBalancer(context.Background(), []string{"capabilities"}, &output, nil, tt.backend); code != tt.code || output.String() != tt.frame+"\n" {
			t.Fatalf("capability frame %q, exit %d", output.String(), code)
		}
	}
}

func TestBalancerInheritedPipeSnapshotAndOptOut(t *testing.T) {
	dir := t.TempDir()
	config, spec := filepath.Join(dir, "config"), filepath.Join(dir, "spec")
	for path, marker := range map[string]string{config: "private config", spec: "private spec"} {
		if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parent, requests := io.Pipe()
	defer requests.Close()
	output, child := io.Pipe()
	defer output.Close()
	frames := make(chan string, 3)
	go func() {
		defer close(frames)
		reader := bufio.NewScanner(output)
		for reader.Scan() {
			frames <- reader.Text()
		}
	}()
	backend := &balancerTestBackend{}
	exited := make(chan int, 1)
	go func() {
		defer child.Close()
		exited <- RunBalancer(ctx, []string{"run", "--config", config, "--managed-inbound", "managed", "--max-lines", "3", "--spec", spec}, child, parent, backend)
	}()
	readFrame := func(expected string) {
		t.Helper()
		select {
		case frame := <-frames:
			if frame != expected || strings.Contains(frame, "private") {
				t.Fatalf("unexpected frame %q", frame)
			}
		case <-ctx.Done():
			t.Fatal("timed out reading a diagnostic frame")
		}
	}
	readFrame(`{"stage":"started","code":0}`)
	if _, err := io.WriteString(requests, "snapshot\n"); err != nil {
		t.Fatal(err)
	}
	readFrame(`{"stage":"selections","code":0,"rows":"4,1,2\n5,1,1"}`)
	if _, err := io.WriteString(requests, "disable\n"); err != nil {
		t.Fatal(err)
	}
	readFrame(`{"stage":"selections","code":0,"rows":""}`)
	requests.Close()
	select {
	case code := <-exited:
		if code != 0 || !backend.stopped || backend.configuration != "private config" || backend.checkedSpec != "private spec" || backend.inbound != "managed" || backend.capacity != 3 {
			t.Fatalf("backend launch or cleanup contract failed, exit %d", code)
		}
	case <-ctx.Done():
		t.Fatal("closing the parent pipe did not stop Core")
	}
}
