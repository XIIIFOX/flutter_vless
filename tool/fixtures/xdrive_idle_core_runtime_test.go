package xdrive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	apppolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const nativeIdleProbeProtocol = "native-xdrive-idle-observer"

type nativeIdleProbeKey struct{}
type nativeIdleProbe struct {
	connection chan *Conn
	read       chan struct{}
	readOnce   sync.Once
}

// The alias observes the actual production transport return and first read. It
// neither substitutes storage nor changes context, Close, bytes or deadlines.
type nativeIdleObservedConn struct {
	*Conn
	probe *nativeIdleProbe
}

func (c *nativeIdleObservedConn) Read(b []byte) (int, error) {
	c.probe.readOnce.Do(func() { close(c.probe.read) })
	return c.Conn.Read(b)
}

var nativeIdleRegistration sync.Once
var nativeIdleRegistrationError error

func registerNativeIdleObservation() error {
	nativeIdleRegistration.Do(func() {
		if err := common.RegisterConfig((*wrapperspb.DoubleValue)(nil), func(ctx context.Context, value interface{}) (interface{}, error) {
			if _, ok := ctx.Value(nativeIdleProbeKey{}).(*nativeIdleProbe); !ok || value.(*wrapperspb.DoubleValue).Value != 173 {
				return nil, errors.New("invalid idle observation marker")
			}
			return ctx, nil
		}); err != nil {
			nativeIdleRegistrationError = err
			return
		}
		if err := internet.RegisterProtocolConfigCreator(nativeIdleProbeProtocol, func() interface{} { return new(Config) }); err != nil {
			nativeIdleRegistrationError = err
			return
		}
		nativeIdleRegistrationError = internet.RegisterTransportDialer(nativeIdleProbeProtocol, func(ctx context.Context, dest xnet.Destination, stream *internet.MemoryStreamConfig) (stat.Connection, error) {
			probe, ok := ctx.Value(nativeIdleProbeKey{}).(*nativeIdleProbe)
			if !ok || core.FromContext(ctx) == nil {
				return nil, errors.New("idle observation requires actual Core dispatch")
			}
			raw, err := Dial(ctx, dest, stream)
			if err != nil {
				return nil, err
			}
			conn, ok := raw.(*Conn)
			if !ok {
				_ = raw.Close()
				return nil, errors.New("unexpected production XDRIVE connection type")
			}
			probe.connection <- conn
			return &nativeIdleObservedConn{Conn: conn, probe: probe}, nil
		})
	})
	return nativeIdleRegistrationError
}

// This diagnostic deliberately uses actual Core.NewWithContext/Start/Dial and
// the ordinary proxyman + SOCKS Process/Close path. It must not infer a Core bug
// from a standalone context or a fabricated feature's Close implementation.
func TestAcceptanceXdriveActualCoreCloseDrainsIdleWorker(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("idle transport diagnostic is remote Actions only")
	}
	if err := registerNativeIdleObservation(); err != nil {
		t.Fatal(err)
	}
	listed := make(chan struct{})
	var listOnce sync.Once
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=synthetic-access/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			_, _ = io.WriteString(w, "<ListBucketResult/>")
			listOnce.Do(func() { close(listed) })
			return
		}
		if r.Method == http.MethodPut {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	probe := &nativeIdleProbe{connection: make(chan *Conn, 1), read: make(chan struct{})}
	parent, forceCancel := context.WithCancel(context.WithValue(context.Background(), nativeIdleProbeKey{}, probe))
	cloud := &Config{Service: "s3", RemoteFolder: "idle-proof", Secrets: []string{"synthetic-access", "synthetic-secret"},
		S3:             &S3Config{Endpoint: service.URL, Bucket: "synthetic-bucket", PathStyle: true},
		PollIntervalMs: 3_600_000, MaxPollIntervalMs: 3_600_000, EagerWindowMs: 1}
	configuration := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&apppolicy.Config{Level: map[uint32]*apppolicy.Policy{0: {Timeout: &apppolicy.Policy_Timeout{Handshake: &apppolicy.Second{Value: 3600}}}}}),
		},
		Outbound: []*core.OutboundHandlerConfig{{Tag: "idle-cloud",
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
				ProtocolName:      nativeIdleProbeProtocol,
				TransportSettings: []*internet.TransportConfig{{ProtocolName: nativeIdleProbeProtocol, Settings: serial.ToTypedMessage(cloud)}},
			}}),
			ProxySettings: serial.ToTypedMessage(&socks.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: 9}}),
		}},
	}
	var instance *core.Instance
	var caller xnet.Conn
	var cloudConn *Conn
	t.Cleanup(func() {
		forceCancel()
		if caller != nil {
			_ = caller.Close()
		}
		if cloudConn != nil {
			_ = cloudConn.Close()
		}
		if instance != nil {
			_ = instance.Close()
		}
		service.CloseClientConnections()
		service.Close()
	})
	var err error
	instance, err = core.NewWithContext(parent, configuration)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := core.CreateObject(instance, wrapperspb.Double(173))
	if err != nil {
		t.Fatal(err)
	}
	coreContext := observed.(context.Context)
	owner, ok := internet.NativeServiceLifetimeFromContext(coreContext)
	if !ok || core.FromContext(coreContext) != instance {
		t.Fatal("actual Core factory did not supply its managed context")
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	caller, err = core.Dial(coreContext, instance, xnet.TCPDestination(xnet.IPAddress(xnet.IP{192, 0, 2, 99}), 80))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case cloudConn = <-probe.connection:
	case <-time.After(3 * time.Second):
		t.Fatal("actual outbound feature did not create an XDRIVE connection")
	}
	for _, ready := range []<-chan struct{}{probe.read, listed} {
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			t.Fatal("actual SOCKS handshake/read or initial cloud poll did not start")
		}
	}
	reader, ok := cloudConn.reader.(*walReader)
	if !ok {
		t.Fatal("S3 fixture did not select actual WAL reader")
	}
	// The SOCKS handshake has already written its greeting (which calls Wake)
	// and is waiting for Read. Once that existing wake is consumed, the empty
	// poll has returned and the reader is in its one-hour idle wait. Do not
	// enqueue another wake into the nested minimum-poll timer.
	deadline := time.Now().Add(2 * time.Second)
	for len(reader.wake) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("WAL worker did not consume idle synchronization wake")
		}
		runtime.Gosched()
	}
	select {
	case <-reader.chunks():
		t.Fatal("WAL reader stopped before the actual Core.Close observation")
	default:
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if parent.Err() != nil || coreContext.Err() != nil {
		t.Fatal("Core.Close cancelled a caller/feature context")
	}
	select {
	case <-owner.Done():
	default:
		t.Fatal("actual Core.Close did not close its cloud service owner")
	}
	select {
	case _, open := <-reader.chunks():
		if open {
			t.Fatal("unexpected cloud payload in idle fixture")
		}
	case <-time.After(time.Second):
		t.Fatal("idle WAL worker survived actual Core.Close; caller/feature contexts preserved")
	}
	t.Log("actual Core/dispatcher/SOCKS/XDRIVE idle reader drained; caller preserved; own cleanup follows")
}
