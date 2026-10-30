package xdrive

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func nativeS3Stream() *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{ProtocolSettings: &Config{Service: "s3", RemoteFolder: "synthetic-prefix",
		Secrets: []string{"synthetic-access", "synthetic-secret"}, S3: &S3Config{Endpoint: "http://127.0.0.1:18095", Bucket: "synthetic-bucket", PathStyle: true}}}
}

func TestNativeXdriveStorageCannotEscapeItsCoreOrCompiledSocketPolicy(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, owner := ContextWithNativeLifetime(parent)
	defer owner.Close()
	second, otherOwner := ContextWithNativeLifetime(parent)
	defer otherOwner.Close()
	stream := nativeS3Stream()
	a, err := newNativeStorage(first, stream)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newNativeStorage(first, stream)
	if err != nil || a != b {
		t.Fatal("same owner/compiled stream lost its cache")
	}
	c, err := newNativeStorage(second, stream)
	if err != nil || a == c {
		t.Fatal("cloud cache escaped into another Core")
	}
	clone := *stream
	clone.SocketSettings = &internet.SocketConfig{Interface: "synthetic-different-underlay"}
	d, err := newNativeStorage(first, &clone)
	if err != nil || a == d {
		t.Fatal("cloud cache reused another compiled socket policy")
	}
	owner.Close()
	owner.Close()
	if owner.storage != nil || parent.Err() != nil || second.Err() != nil {
		t.Fatal("close retained cache or cancelled a foreign owner")
	}
	select {
	case <-owner.Done():
	default:
		t.Fatal("Core lifetime was not cancelled")
	}
	if _, err := newNativeStorage(first, stream); err == nil {
		t.Fatal("closed Core admitted a cloud request")
	}
	if _, err := newNativeStorage(first, nil); err == nil {
		t.Fatal("nil stream accepted")
	}
}

type nativeBlockingTransport struct {
	started chan struct{}
	once    sync.Once
}

func (n *nativeBlockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	n.once.Do(func() { close(n.started) })
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestNativeXdriveCoreCloseCancelsTokenOrServiceRequestWithoutStallWait(t *testing.T) {
	parent, forcedCancel := context.WithCancel(context.Background())
	defer forcedCancel()
	ctx, owner := ContextWithNativeLifetime(parent)
	defer owner.Close()
	blocked := &nativeBlockingTransport{started: make(chan struct{})}
	transport := &serviceTransport{owner: ctx, plain: blocked, secure: blocked, stall: time.Minute}
	request, _ := http.NewRequestWithContext(context.Background(), "GET", "http://no-socket.invalid/", nil)
	done := make(chan error, 1)
	go func() { _, err := transport.RoundTrip(request); done <- err }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("controlled request did not start")
	}
	owner.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request survived Core.Close")
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("closed transport admitted another request")
	}
}

func TestNativeXdriveOperationKeepsCoreValuesAndCancelsRetryWait(t *testing.T) {
	type identity struct{}
	request := context.WithValue(context.Background(), identity{}, "owned-core-value")
	ctx, owner := ContextWithNativeLifetime(context.Background())
	defer owner.Close()
	operation, release := nativeOperationContext(request, ctx)
	defer release()
	if operation.Value(identity{}) != "owned-core-value" {
		t.Fatal("operation lost caller metadata")
	}
	owner.Close()
	select {
	case <-operation.Done():
	case <-time.After(time.Second):
		t.Fatal("operation/retry context survived owner close")
	}
	if request.Err() != nil {
		t.Fatal("operation cancelled caller context")
	}
}
