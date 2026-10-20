package dns

// These tests use actual Classic/DNS/UDP-dispatcher methods with memory-only
// links. They construct no Core instance, socket, listener or real resolver.
import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/dns/dnsmessage"
)

type nativeClassicReader struct {
	done, entered, returned     chan struct{}
	once, enterOnce, returnOnce sync.Once
	interrupts                  atomic.Int64
}

func (r *nativeClassicReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.done
	r.returnOnce.Do(func() { close(r.returned) })
	return nil, io.EOF
}
func (r *nativeClassicReader) Interrupt() {
	r.interrupts.Add(1)
	r.force()
}
func (r *nativeClassicReader) force() { r.once.Do(func() { close(r.done) }) }

type nativeClassicWriter struct {
	mu              sync.Mutex
	packets         [][]byte
	block           bool
	done, entered   chan struct{}
	once, enterOnce sync.Once
	interrupts      atomic.Int64
}

func (w *nativeClassicWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	w.mu.Lock()
	for _, packet := range packets {
		w.packets = append(w.packets, append([]byte(nil), packet.Bytes()...))
	}
	w.mu.Unlock()
	w.enterOnce.Do(func() { close(w.entered) })
	if w.block {
		<-w.done
		return io.ErrClosedPipe
	}
	return nil
}
func (w *nativeClassicWriter) Interrupt() { w.interrupts.Add(1); w.force() }
func (w *nativeClassicWriter) force()     { w.once.Do(func() { close(w.done) }) }
func (w *nativeClassicWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.packets...)
}

type nativeClassicDispatcher struct {
	reader      *nativeClassicReader
	writer      *nativeClassicWriter
	calls       atomic.Int64
	ctx         context.Context
	destination xnet.Destination
	failure     error
}

func (*nativeClassicDispatcher) Type() any    { return routing.DispatcherType() }
func (*nativeClassicDispatcher) Start() error { return nil }
func (*nativeClassicDispatcher) Close() error { return nil }
func (d *nativeClassicDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	d.ctx, d.destination = ctx, destination
	d.calls.Add(1)
	if d.failure != nil {
		return nil, d.failure
	}
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}
func (*nativeClassicDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("unexpected memory DispatchLink")
}

func nativeClassicFixture(t *testing.T, address string, blocked bool) (*ClassicNameServer, *nativeClassicDispatcher, context.Context) {
	t.Helper()
	d := &nativeClassicDispatcher{
		reader: &nativeClassicReader{done: make(chan struct{}), entered: make(chan struct{}), returned: make(chan struct{})},
		writer: &nativeClassicWriter{block: blocked, done: make(chan struct{}), entered: make(chan struct{})},
	}
	s := NewClassicNameServer(xnet.UDPDestination(xnet.ParseAddress(address), 18053), d, true, false, 0, nil)
	// Only an identity token for toDnsContext; not core.New/Start/Build.
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	t.Cleanup(func() {
		d.reader.force()
		d.writer.force()
		s.udpServer.RemoveRay()
		_ = s.requestsCleanup.Close()
	})
	return s, d, ctx
}
func nativeClassicAwait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(label + " did not drain")
	}
}
func nativeClassicSend(s *ClassicNameServer, ctx context.Context) chan error {
	failures := make(chan error, 2)
	s.sendQuery(ctx, failures, "owned.invalid.", featuredns.IPOption{IPv4Enable: true})
	return failures
}

func TestNativeClassicLifetimeClosesBothFamilies(t *testing.T) {
	for _, address := range []string{"192.0.2.53", "2001:db8::53"} {
		t.Run(address, func(t *testing.T) {
			s, d, base := nativeClassicFixture(t, address, false)
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			failures := nativeClassicSend(s, ctx)
			nativeClassicAwait(t, d.reader.entered, "memory reader entry")
			if len(failures) != 0 || d.calls.Load() != 1 || len(d.writer.snapshot()) != 1 || d.destination.Address.String() != address {
				t.Fatal("query control did not create the exact numeric ray")
			}
			cancel()
			if d.ctx.Err() != nil || d.reader.interrupts.Load() != 0 {
				t.Fatal("caller cancellation control unexpectedly owned detached DNS ray")
			}
			owner := &DNS{clients: []*Client{{server: s}}}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			nativeClassicAwait(t, d.reader.returned, "closed memory reader")
			if d.ctx.Err() == nil || d.reader.interrupts.Load() != 1 || d.writer.interrupts.Load() != 1 {
				t.Fatal("DNS.Close did not interrupt its actual Classic ray once")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if d.reader.interrupts.Load() != 1 || d.writer.interrupts.Load() != 1 {
				t.Fatal("repeated Close repeated ray interruption")
			}
			late := nativeClassicSend(s, base)
			if len(late) != 1 || d.calls.Load() != 1 || len(d.writer.snapshot()) != 1 {
				t.Fatal("closed server admitted another query")
			}
			s.RLock()
			pending := len(s.requests)
			s.RUnlock()
			if pending != 0 {
				t.Fatal("closed server retained pending requests")
			}
		})
	}
}

func TestNativeClassicLifetimeClosesBeforeQueryAndConcurrentClose(t *testing.T) {
	s, d, ctx := nativeClassicFixture(t, "2001:db8::53", false)
	owner := &DNS{clients: []*Client{{server: s}}}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() { defer workers.Done(); _ = owner.Close() }()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	nativeClassicAwait(t, done, "concurrent Close")
	if failures := nativeClassicSend(s, ctx); len(failures) != 1 || d.calls.Load() != 0 {
		t.Fatal("Close-before-query created a ray")
	}
	if d.reader.interrupts.Load() != 0 || d.writer.interrupts.Load() != 0 {
		t.Fatal("uncreated ray received fabricated interruption")
	}
}

func TestNativeClassicLifetimeInterruptsBlockedDispatch(t *testing.T) {
	for _, address := range []string{"192.0.2.53", "2001:db8::53"} {
		t.Run(address, func(t *testing.T) {
			s, d, ctx := nativeClassicFixture(t, address, true)
			sent := make(chan struct{})
			go func() { nativeClassicSend(s, ctx); close(sent) }()
			nativeClassicAwait(t, d.writer.entered, "blocked memory writer entry")
			nativeClassicAwait(t, d.reader.entered, "blocked memory reader entry")
			closed := make(chan struct{})
			go func() { _ = (&DNS{clients: []*Client{{server: s}}}).Close(); close(closed) }()
			nativeClassicAwait(t, closed, "Close across blocked Dispatch")
			nativeClassicAwait(t, sent, "blocked Dispatch")
			nativeClassicAwait(t, d.reader.returned, "blocked ray reader")
			if d.reader.interrupts.Load() != 1 || d.writer.interrupts.Load() != 1 {
				t.Fatal("Close could not interrupt I/O outside lifecycle lock")
			}
		})
	}
}

func TestNativeClassicLifetimeRegistrationStartCloseOrder(t *testing.T) {
	s, d, ctx := nativeClassicFixture(t, "192.0.2.53", false)
	entered, release := make(chan struct{}), make(chan struct{})
	var execute atomic.Int64
	s.requestsCleanup.Execute = func() error { execute.Add(1); close(entered); <-release; return s.RequestsCleanup() }
	sent := make(chan struct{})
	go func() { nativeClassicSend(s, ctx); close(sent) }()
	nativeClassicAwait(t, entered, "Periodic.Start synchronous Execute")
	closed := make(chan struct{})
	go func() { _ = (&DNS{clients: []*Client{{server: s}}}).Close(); close(closed) }()
	close(release)
	nativeClassicAwait(t, sent, "admitted registration")
	nativeClassicAwait(t, closed, "registration vs Close")
	if failures := nativeClassicSend(s, ctx); len(failures) != 1 || execute.Load() != 1 || d.calls.Load() > 1 {
		t.Fatal("late registration restarted Periodic or dispatcher")
	}
	s.RLock()
	pending := len(s.requests)
	s.RUnlock()
	if pending != 0 {
		t.Fatal("Close did not clear admitted request")
	}
}

func nativeClassicTruncated(t *testing.T, id uint16) *protocoludp.Packet {
	t.Helper()
	name, err := dnsmessage.NewName("owned.invalid.")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true, Truncated: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &protocoludp.Packet{Payload: buf.FromBytes(packet)}
}
func TestNativeClassicLifetimeEDNSRetryAndLateAdmission(t *testing.T) {
	s, d, ctx := nativeClassicFixture(t, "2001:db8::53", false)
	nativeClassicSend(s, ctx)
	first := d.writer.snapshot()
	var request dnsmessage.Message
	if len(first) != 1 || request.Unpack(first[0]) != nil || len(request.Additionals) != 0 {
		t.Fatal("EDNS first-query control is vacuous")
	}
	s.HandleResponse(ctx, nativeClassicTruncated(t, request.ID))
	second := d.writer.snapshot()
	if len(second) != 2 {
		t.Fatal("live truncated response did not retry with EDNS")
	}
	var retried dnsmessage.Message
	if retried.Unpack(second[1]) != nil || len(retried.Additionals) != 1 {
		t.Fatal("retry did not add exactly one EDNS option")
	}
	s.RLock()
	held := s.requests[retried.ID]
	s.RUnlock()
	if held == nil {
		t.Fatal("live retry has no pending registration")
	}
	_ = (&DNS{clients: []*Client{{server: s}}}).Close()
	// A response arriving after Close and a retry already holding its copied
	// request both share the same final registration fence.
	s.HandleResponse(ctx, nativeClassicTruncated(t, retried.ID))
	if s.addPendingRequest(held) || len(d.writer.snapshot()) != 2 {
		t.Fatal("closed server revived an EDNS retry")
	}
}

func TestNativeClassicLifetimeClosedDispatcherReleasesPayload(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed", true: "dispatch-error"}[failed], func(t *testing.T) {
			s, d, ctx := nativeClassicFixture(t, "192.0.2.53", false)
			if failed {
				d.failure = errors.New("inert dispatch refusal")
			} else {
				s.udpServer.RemoveRay()
			}
			payload := buf.New()
			_, _ = payload.Write([]byte{1, 2, 3})
			s.udpServer.Dispatch(ctx, xnet.UDPDestination(xnet.ParseAddress("192.0.2.53"), 18053), payload)
			if !payload.IsEmpty() {
				payload.Release()
				t.Fatal("dispatcher rejection leaked its owned payload")
			}
			want := int64(0)
			if failed {
				want = 1
			}
			if d.calls.Load() != want {
				t.Fatal("terminal refusal created an unexpected ray")
			}
		})
	}
}
