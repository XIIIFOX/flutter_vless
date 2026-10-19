package nativecli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	capability int64
	checkCode  int64
	events     []string
	check      func([]byte, []byte)
	start      func([]byte, []byte) error
}

func (b *fakeBackend) Capability() int64 {
	b.events = append(b.events, "capability")
	return b.capability
}
func (b *fakeBackend) Check(config, spec []byte) int64 {
	b.events = append(b.events, "check")
	if b.check != nil {
		b.check(config, spec)
	}
	return b.checkCode
}
func (b *fakeBackend) Start(config, spec []byte) error {
	b.events = append(b.events, "start")
	if b.start != nil {
		return b.start(config, spec)
	}
	return nil
}
func (b *fakeBackend) Stop() { b.events = append(b.events, "stop") }

func cliPaths(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	return filepath.Join(directory, "config.json"), filepath.Join(directory, "spec.json")
}

func noRead(t *testing.T) func(string) ([]byte, error) {
	t.Helper()
	return func(string) ([]byte, error) { t.Fatal("unexpected file read"); return nil, nil }
}

func TestNativeCLIGrammarAndCapabilityBeforeRead(t *testing.T) {
	config, spec := cliPaths(t)
	for _, args := range [][]string{
		nil, {"unknown"}, {"capabilities", "--config", config}, {"check"},
		{"check", "--config", config}, {"run", "--spec", spec},
		{"check", "--config", "relative.json", "--spec", spec},
		{"check", "--config", config, "--spec", ""},
		{"check", "--config", config, "--spec", spec, "extra"},
		{"check", "--config=" + config, "--spec", spec},
		{"check", "--config", config, "--config", spec},
		{"check", "--config", config, "--unknown", spec},
	} {
		backend := &fakeBackend{capability: 1}
		var out bytes.Buffer
		if code := run(context.Background(), args, &out, backend, noRead(t)); code != 2 || len(backend.events) != 0 || out.String() != "{\"stage\":\"arguments\",\"code\":2}\n" {
			t.Fatal("invalid grammar had effects or exposed input", code, backend.events, out.String())
		}
	}
	for _, capability := range []int64{0, 2} {
		for _, command := range []string{"capabilities", "check", "run"} {
			args := []string{command}
			if command != "capabilities" {
				args = append(args, "--config", config, "--spec", spec)
			}
			backend := &fakeBackend{capability: capability}
			var out bytes.Buffer
			if code := run(context.Background(), args, &out, backend, noRead(t)); code != 32 || !reflect.DeepEqual(backend.events, []string{"capability"}) || out.String() != "{\"stage\":\"capabilities\",\"code\":32,\"capability\":0}\n" {
				t.Fatal("unsupported backend was used", code, backend.events, out.String())
			}
		}
	}
	backend := &fakeBackend{capability: 1}
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"capabilities"}, &out, backend); code != 0 || out.String() != "{\"stage\":\"capabilities\",\"code\":0,\"capability\":1}\n" || !reflect.DeepEqual(backend.events, []string{"capability"}) {
		t.Fatal("capability result changed", code, backend.events, out.String())
	}
}

func TestNativeCLICheckAndInputFailures(t *testing.T) {
	configPath, specPath := cliPaths(t)
	args := []string{"check", "--spec", specPath, "--config", configPath}
	config, spec := []byte("synthetic secret config"), []byte("synthetic secret spec")
	for _, checkCode := range []int64{0, 1, 2, 3, 5, 16, 17, 18, 19, 20, 21, 32, -1, 7, 1000000} {
		backend := &fakeBackend{capability: 1, checkCode: checkCode}
		backend.check = func(c, s []byte) {
			if !bytes.Equal(c, config) || !bytes.Equal(s, spec) {
				t.Fatal("check received changed bytes")
			}
		}
		var reads []string
		read := func(path string) ([]byte, error) {
			reads = append(reads, path)
			if path == configPath {
				return bytes.Clone(config), nil
			}
			return bytes.Clone(spec), nil
		}
		var out bytes.Buffer
		code := run(context.Background(), args, &out, backend, read)
		want := int(checkCode)
		if checkCode < 0 || checkCode > 32 || checkCode == 7 {
			want = 4
		}
		if code != want || !reflect.DeepEqual(backend.events, []string{"capability", "check"}) || !reflect.DeepEqual(reads, []string{configPath, specPath}) || strings.Contains(out.String(), "secret") {
			t.Fatal("check used runtime or lost fixed result", code, backend.events, reads, out.String())
		}
	}
	for _, failed := range []string{configPath, specPath} {
		backend := &fakeBackend{capability: 1}
		var out bytes.Buffer
		code := run(context.Background(), args, &out, backend, func(path string) ([]byte, error) {
			if path == failed {
				return nil, errors.New("secret input error: " + path)
			}
			return config, nil
		})
		if code != 1 || !reflect.DeepEqual(backend.events, []string{"capability"}) || out.String() != "{\"stage\":\"input\",\"code\":1}\n" {
			t.Fatal("input failure escaped or reached backend", code, backend.events, out.String())
		}
	}
}

type callbackWriter struct {
	bytes.Buffer
	callback func()
	fail     bool
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	if w.callback != nil {
		w.callback()
	}
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

func TestNativeCLIRunOwnsSameBytesAndStop(t *testing.T) {
	configPath, specPath := cliPaths(t)
	args := []string{"run", "--config", configPath, "--spec", specPath}
	for _, publishFails := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		backend := &fakeBackend{capability: 1}
		var readCount int
		read := func(path string) ([]byte, error) { readCount++; return []byte("original:" + path), nil }
		var checkedConfig, checkedSpec []byte
		backend.check = func(c, s []byte) { checkedConfig, checkedSpec = bytes.Clone(c), bytes.Clone(s) }
		backend.start = func(c, s []byte) error {
			if !bytes.Equal(c, checkedConfig) || !bytes.Equal(s, checkedSpec) {
				t.Fatal("Start reread or changed the checked pair")
			}
			return nil
		}
		out := &callbackWriter{callback: cancel, fail: publishFails}
		code := run(ctx, args, out, backend, read)
		cancel()
		want := 0
		if publishFails {
			want = 4
		}
		if code != want || readCount != 2 || !reflect.DeepEqual(backend.events, []string{"capability", "check", "start", "stop"}) {
			t.Fatal("run lost owned stop or checked bytes", code, readCount, backend.events)
		}
		if !publishFails && out.String() != "{\"stage\":\"started\",\"code\":0}\n{\"stage\":\"stopped\",\"code\":0}\n" {
			t.Fatal("unexpected lifecycle output", out.String())
		}
	}
}

func TestNativeCLIRunRefusesBeforeStartAndOwnsCancellation(t *testing.T) {
	config, spec := cliPaths(t)
	args := []string{"run", "--config", config, "--spec", spec}
	for _, stage := range []string{"check", "start", "cancel-before", "cancel-check", "cancel-start"} {
		ctx, cancel := context.WithCancel(context.Background())
		backend := &fakeBackend{capability: 1}
		if stage == "check" {
			backend.checkCode = 21
		}
		if stage == "cancel-before" {
			cancel()
		}
		backend.check = func([]byte, []byte) {
			if stage == "cancel-check" {
				cancel()
			}
		}
		backend.start = func([]byte, []byte) error {
			if stage == "cancel-start" {
				cancel()
			}
			if stage == "start" {
				return errors.New("secret backend failure")
			}
			return nil
		}
		var out bytes.Buffer
		code := run(ctx, args, &out, backend, func(string) ([]byte, error) { return []byte("secret"), nil })
		cancel()
		wantEvents := map[string][]string{
			"check":         {"capability", "check"},
			"start":         {"capability", "check", "start"},
			"cancel-before": nil,
			"cancel-check":  {"capability", "check"},
			"cancel-start":  {"capability", "check", "start", "stop"},
		}[stage]
		wantCode := map[string]int{"check": 21, "start": 4, "cancel-before": 130, "cancel-check": 130, "cancel-start": 0}[stage]
		if code != wantCode || !reflect.DeepEqual(backend.events, wantEvents) || strings.Contains(out.String(), "secret") || (stage == "cancel-start" && strings.Contains(out.String(), "started")) {
			t.Fatal("failure/cancellation changed runtime ownership", stage, code, backend.events, out.String())
		}
	}
}

func TestNativeCLIRunWaitsForCancellation(t *testing.T) {
	config, spec := cliPaths(t)
	ctx, cancel := context.WithCancel(context.Background())
	backend := &fakeBackend{capability: 1}
	published := make(chan struct{}, 1)
	out := &callbackWriter{callback: func() {
		select {
		case published <- struct{}{}:
		default:
		}
	}}
	done := make(chan int, 1)
	finished := false
	defer func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("owned fake run did not drain")
			}
		}
	}()
	go func() {
		done <- run(ctx, []string{"run", "--config", config, "--spec", spec}, out, backend, func(string) ([]byte, error) { return []byte("synthetic"), nil })
	}()
	select {
	case <-published:
	case <-done:
		finished = true
		t.Fatal("run ended before publication")
	case <-time.After(time.Second):
		t.Fatal("fake run did not publish")
	}
	select {
	case <-done:
		finished = true
		t.Fatal("run stopped without cancellation")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case code := <-done:
		finished = true
		if code != 0 || !reflect.DeepEqual(backend.events, []string{"capability", "check", "start", "stop"}) {
			t.Fatal("canceled run did not stop exactly once", code, backend.events)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled fake run did not drain")
	}
}
