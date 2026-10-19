//go:build flutter_vless_vpn_routing_cli

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// All backends and parent pipes here are inert. Never construct or start Core.
type parentFixtureBackend struct {
	capability            int64
	code                  int64
	started               chan struct{}
	checks, starts, stops atomic.Int32
}

func (b *parentFixtureBackend) Capability() int64       { return b.capability }
func (b *parentFixtureBackend) Check(_, _ []byte) int64 { b.checks.Add(1); return b.code }
func (b *parentFixtureBackend) Start(_, _ []byte) error {
	b.starts.Add(1)
	close(b.started)
	return nil
}
func (b *parentFixtureBackend) Stop() { b.stops.Add(1) }

func parentFixtureArgs(t *testing.T) []string {
	t.Helper()
	directory := t.TempDir()
	config, spec := filepath.Join(directory, "config.json"), filepath.Join(directory, "spec.json")
	for _, path := range []string{config, spec} {
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"run", "--parent-stdin", "--config", config, "--spec", spec}
}
func parentFixtureWait(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(2 * time.Second):
		t.Fatal("owned parent observer did not drain")
		return -1
	}
}

func TestNativeRoutingCLIParentInputLifecycle(t *testing.T) {
	for _, stop := range []string{"eof", "signal"} {
		t.Run(stop, func(t *testing.T) {
			backend := &parentFixtureBackend{capability: 1, started: make(chan struct{})}
			reader, writer := io.Pipe()
			defer writer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			args := parentFixtureArgs(t)
			var output bytes.Buffer
			done := make(chan int, 1)
			go func() { done <- runNativeRoutingCommand(ctx, args, &output, backend, reader) }()
			select {
			case <-backend.started:
			case <-time.After(2 * time.Second):
				t.Fatal("private parent-owned run did not start")
			}
			if stop == "eof" {
				writer.Close()
			} else {
				cancel()
			}
			if code := parentFixtureWait(t, done); code != 0 {
				t.Fatal("owned run failed", code)
			}
			if backend.checks.Load() != 1 || backend.starts.Load() != 1 || backend.stops.Load() != 1 {
				t.Fatal("factory ownership was not exactly once")
			}
			if output.String() != "{\"stage\":\"started\",\"code\":0}\n{\"stage\":\"stopped\",\"code\":0}\n" {
				t.Fatal("private lifecycle status contract changed")
			}
			if _, err := writer.Write([]byte("late")); err == nil {
				t.Fatal("owned parent read end retained after exit")
			}
		})
	}
}

func TestNativeRoutingCLIParentInputRefusal(t *testing.T) {
	for _, phase := range []string{"capability", "check"} {
		t.Run(phase, func(t *testing.T) {
			backend := &parentFixtureBackend{capability: 1, code: 3, started: make(chan struct{})}
			want := 3
			if phase == "capability" {
				backend.capability = 0
				want = 32
			}
			reader, writer := io.Pipe()
			defer writer.Close()
			var output bytes.Buffer
			code := runNativeRoutingCommand(context.Background(), parentFixtureArgs(t), &output, backend, reader)
			if code != want || backend.starts.Load() != 0 || backend.stops.Load() != 0 {
				t.Fatal("refused candidate reached Start or changed its error", code)
			}
			if _, err := writer.Write([]byte("late")); err == nil {
				t.Fatal("refusal retained the parent input")
			}
		})
	}
}

type forbiddenParentInput struct{}

func (forbiddenParentInput) Read([]byte) (int, error) {
	panic("ordinary/invalid command read parent input")
}
func (forbiddenParentInput) Close() error { panic("ordinary/invalid command closed parent input") }

func TestNativeRoutingCLIParentInputGrammar(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--parent-stdin", "--config", "/config", "--spec", "/spec"},
		{"run", "--config", "/config", "--parent-stdin", "--spec", "/spec"},
		{"run", "--parent-stdin", "--parent-stdin", "--config", "/config", "--spec", "/spec"},
		{"run", "--parent-stdin"},
	} {
		backend := &parentFixtureBackend{capability: 1, started: make(chan struct{})}
		var output bytes.Buffer
		if code := runNativeRoutingCommand(context.Background(), args, &output, backend, forbiddenParentInput{}); code != 2 {
			t.Fatal("invalid parent flag grammar admitted", code)
		}
		if !strings.Contains(output.String(), "\"stage\":\"arguments\"") || backend.checks.Load() != 0 {
			t.Fatal("invalid arguments reached backend")
		}
	}
}

func TestNativeRoutingCLIParentInputOrdinaryForeground(t *testing.T) {
	args := parentFixtureArgs(t)
	args = append(args[:1], args[2:]...)
	backend := &parentFixtureBackend{capability: 1, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- runNativeRoutingCommand(ctx, args, &output, backend, forbiddenParentInput{}) }()
	select {
	case <-backend.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary foreground failed to start")
	}
	cancel()
	if code := parentFixtureWait(t, done); code != 0 || backend.stops.Load() != 1 {
		t.Fatal("ordinary signal lifecycle changed")
	}
}
