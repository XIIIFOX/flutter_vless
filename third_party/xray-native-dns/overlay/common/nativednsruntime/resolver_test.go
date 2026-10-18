package nativednsruntime

// Pure in-memory handlers/pipes; no Core construction, listeners or DNS sockets.
import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	proxyoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type fakeDNS struct{}

func (*fakeDNS) Type() any                                               { return dns.ClientType() }
func (*fakeDNS) Start() error                                            { return nil }
func (*fakeDNS) Close() error                                            { return nil }
func (*fakeDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) { panic("root DNS recursion") }

type memoryHandler struct {
	name    string
	allowed bool
	run     func(context.Context, *transport.Link)
}

func (h *memoryHandler) Tag() string                        { return h.name }
func (*memoryHandler) Start() error                         { return nil }
func (*memoryHandler) Close() error                         { return nil }
func (*memoryHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*memoryHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *memoryHandler) NativeDNSPolicyEgressAllowed() bool { return h.allowed }
func (h *memoryHandler) Dispatch(ctx context.Context, link *transport.Link) {
	if h.run != nil {
		h.run(ctx, link)
	}
}

func runtimeFixture(t *testing.T, handlers ...*memoryHandler) (*internet.NativeDNSOwner, *core.Instance, context.Context) {
	t.Helper()
	bindings := make([]internet.NativeDNSBinding, len(handlers))
	for index := range handlers {
		bindings[index] = internet.NativeDNSBinding{Key: new(int), SourceIndex: index, Tag: handlers[index].name, ProxyType: "xray.proxy.freedom.Config"}
	}
	owner, err := internet.NewNativeDNSOwner(bindings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	instance := new(core.Instance) // identity value only; never New/Start/GetFeature
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = internet.ContextWithNativeDNSOwner(ctx, owner)
	manager, err := proxyoutbound.New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for index, handler := range handlers {
		scope, err := internet.BindNativeDNSHandler(ctx, instance, bindings[index].Key, handler.Tag(), bindings[index].ProxyType, &fakeDNS{}, manager)
		if err != nil {
			t.Fatal(err)
		}
		if err := scope.RegisterRuntime(handler); err != nil {
			t.Fatal(err)
		}
		if err := manager.AddHandler(ctx, handler); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.SealNativeDNSRuntime(instance, manager); err != nil {
		t.Fatal(err)
	}
	return owner, instance, ctx
}

func resolverFixture(t *testing.T, timeout time.Duration, handlers ...*memoryHandler) (*TCPResolver, context.Context) {
	t.Helper()
	owner, instance, ctx := runtimeFixture(t, handlers...)
	resolver, err := NewTCPResolver(owner, len(handlers)-1, net.TCPDestination(net.LocalHostIP, 5353), timeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Bind(instance); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := resolver.Close(); err != nil {
			t.Error(err)
		}
	})
	return resolver, ctx
}

func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned operation did not finish")
	}
}

func TestNativeDNSPolicyUsesExactUntaggedIndexAndFreshMetadata(t *testing.T) {
	seen := make(chan context.Context, 2)
	wrong := &memoryHandler{allowed: true, run: func(context.Context, *transport.Link) { t.Error("wrong source index") }}
	selected := &memoryHandler{allowed: true, run: func(ctx context.Context, link *transport.Link) {
		seen <- ctx
		request, err := link.Reader.ReadMultiBuffer()
		if err == nil {
			_ = link.Writer.WriteMultiBuffer(request)
		}
	}}
	resolver, ctx := resolverFixture(t, time.Second, wrong, selected)
	callerInbound, callerOutbound, callerContent := &session.Inbound{Tag: "caller"}, &session.Outbound{Tag: "caller"}, &session.Content{Attributes: map[string]string{"private": "caller"}}
	ctx = session.ContextWithInbound(ctx, callerInbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{callerOutbound})
	ctx = session.ContextWithContent(ctx, callerContent)
	contexts := make([]context.Context, 0, 2)
	for _, payload := range []string{"owner-A", "fresh-B"} {
		link, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination)
		if err != nil {
			t.Fatal(err)
		}
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte(payload))); err != nil {
			t.Fatal(err)
		}
		reply, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		var output []byte
		for _, buffer := range reply {
			output = append(output, buffer.Bytes()...)
		}
		buf.ReleaseMulti(reply)
		if string(output) != payload {
			t.Fatalf("reply discarded: %q", output)
		}
		contexts = append(contexts, <-seen)
		link.Reader.(*policyReader).Interrupt()
	}
	for _, request := range contexts {
		inbound, content := session.InboundFromContext(request), session.ContentFromContext(request)
		outbounds := session.OutboundsFromContext(request)
		if inbound == callerInbound || inbound.User != nil || inbound.Tag != "" || inbound.Conn != nil || content == callerContent ||
			!content.SkipDNSResolve || len(content.Attributes) != 0 || len(outbounds) != 1 || outbounds[0] == callerOutbound || outbounds[0].Tag != "" {
			t.Fatal("native default inherited caller routing/user metadata")
		}
	}
	if session.ContentFromContext(contexts[0]) == session.ContentFromContext(contexts[1]) ||
		session.OutboundsFromContext(contexts[0])[0] == session.OutboundsFromContext(contexts[1])[0] {
		t.Fatal("parallel requests share mutable metadata")
	}
}

func TestNativeDNSPolicyCloseAndDeadlineInterruptOwnedPipes(t *testing.T) {
	for _, cause := range []string{"close", "deadline", "owner"} {
		t.Run(cause, func(t *testing.T) {
			entered, ended := make(chan struct{}), make(chan struct{})
			handler := &memoryHandler{allowed: true, run: func(ctx context.Context, _ *transport.Link) { close(entered); <-ctx.Done(); close(ended) }}
			resolver, ctx := resolverFixture(t, 80*time.Millisecond, handler)
			link, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination)
			if err != nil {
				t.Fatal(err)
			}
			wait(t, entered)
			switch cause {
			case "close":
				if err := resolver.Close(); err != nil {
					t.Fatal(err)
				}
			case "owner":
				_ = resolver.dispatcher.owner.Close()
			}
			readDone := make(chan struct{})
			go func() {
				buffers, err := link.Reader.ReadMultiBuffer()
				buf.ReleaseMulti(buffers)
				if err == nil {
					t.Error("closed pipe returned success")
				}
				close(readDone)
			}()
			wait(t, readDone)
			wait(t, ended)
			if cause != "deadline" {
				if _, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination); err == nil {
					t.Fatal("closed owner accepted work")
				}
			}
		})
	}
}

func TestNativeDNSPolicyRejectsForeignAndUnapprovedRequestsBeforeDispatch(t *testing.T) {
	resolver, ctx := resolverFixture(t, time.Second, &memoryHandler{allowed: true, run: func(context.Context, *transport.Link) { t.Error("refused request reached handler") }})
	for _, destination := range []net.Destination{
		net.TCPDestination(net.DomainAddress("resolver.invalid"), 5353), net.TCPDestination(net.LocalHostIP, 5354),
		net.UDPDestination(net.LocalHostIP, 5353), net.TCPDestination(net.ParseAddress("127.0.0.2"), 5353),
	} {
		if _, err := resolver.dispatcher.Dispatch(ctx, destination); err == nil {
			t.Fatal("unapproved resolver accepted")
		}
	}
	foreign := context.WithValue(ctx, core.XrayKey(1), new(core.Instance))
	if _, err := resolver.dispatcher.Dispatch(foreign, resolver.dispatcher.destination); !errors.Is(err, internet.ErrNativeDNSIdentity) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := resolver.dispatcher.Dispatch(cancelled, resolver.dispatcher.destination); err == nil {
		t.Fatal("canceled query accepted")
	}
	if err := resolver.dispatcher.DispatchLink(ctx, resolver.dispatcher.destination, nil); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
}

type fakeServer struct {
	query func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error)
}

func (*fakeServer) Name() string         { return "pure" }
func (*fakeServer) IsDisableCache() bool { return true }
func (s *fakeServer) QueryIP(ctx context.Context, name string, option dns.IPOption) ([]net.IP, uint32, error) {
	return s.query(ctx, name, option)
}

func TestNativeDNSDelegateReadyOnceAndLateResultRefusal(t *testing.T) {
	owner, instance, ctx := runtimeFixture(t, &memoryHandler{allowed: true})
	resolver, err := NewTCPResolver(owner, 0, net.TCPDestination(net.LocalHostIP, 5353), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	if _, _, err := resolver.LookupIPContext(ctx, "query.invalid", dns.IPOption{IPv4Enable: true}); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	if err := resolver.Bind(instance); err != nil {
		t.Fatal(err)
	}
	if err := resolver.Bind(instance); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
	var shared = []net.IP{net.ParseIP("192.0.2.42")}
	resolver.newServer = func(context.Context) (appdns.Server, error) {
		return &fakeServer{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) { return shared, 91, nil }}, nil
	}
	answer, ttl, err := resolver.LookupIPContext(ctx, "query.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || ttl != 91 || len(answer) != 1 {
		t.Fatalf("%v %d %v", answer, ttl, err)
	}
	answer[0][0] ^= 1
	if answer[0].Equal(shared[0]) {
		t.Fatal("delegate returned mutable server IP storage")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resolver.newServer = func(context.Context) (appdns.Server, error) {
		return &fakeServer{query: func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error) {
			close(entered)
			<-release
			return shared, 91, nil
		}}, nil
	}
	go func() {
		_, _, err := resolver.LookupIPContext(ctx, "query.invalid", dns.IPOption{IPv4Enable: true})
		if err == nil {
			t.Error("late closed result accepted")
		}
		close(done)
	}()
	wait(t, entered)
	_ = resolver.Close()
	close(release)
	wait(t, done)
	if err := resolver.Bind(instance); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestNativeDNSRuntimeSealingRejectsMutationAndForeignIdentities(t *testing.T) {
	key, instance := new(int), new(core.Instance)
	owner, err := internet.NewNativeDNSOwner([]internet.NativeDNSBinding{{Key: key, SourceIndex: 0, ProxyType: "xray.proxy.freedom.Config"}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	manager, _ := proxyoutbound.New(context.Background(), &proxyman.OutboundConfig{})
	ctx := internet.ContextWithNativeDNSOwner(context.Background(), owner)
	if err := owner.SealNativeDNSRuntime(instance, manager); err == nil {
		t.Fatal("sealed before construction")
	}
	scope, err := internet.BindNativeDNSHandler(ctx, instance, key, "", "xray.proxy.freedom.Config", &fakeDNS{}, manager)
	if err != nil {
		t.Fatal(err)
	}
	handler := &memoryHandler{allowed: true}
	if err := scope.RegisterRuntime(handler); err != nil {
		t.Fatal(err)
	}
	if err := scope.RegisterRuntime(handler); err == nil {
		t.Fatal("duplicate runtime accepted")
	}
	if err := owner.SealNativeDNSRuntime(instance, manager); err == nil {
		t.Fatal("missing manager membership accepted")
	}
	if err := manager.AddHandler(ctx, handler); err != nil {
		t.Fatal(err)
	}
	if err := owner.SealNativeDNSRuntime(new(core.Instance), manager); err == nil {
		t.Fatal("foreign Core accepted")
	}
	if err := owner.SealNativeDNSRuntime(instance, manager); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(ctx, &memoryHandler{name: "new"}); err == nil {
		t.Fatal("sealed add accepted")
	}
	if err := manager.RemoveHandler(ctx, "any"); err == nil {
		t.Fatal("sealed remove accepted")
	}
	if got, _, err := owner.NativeDNSRuntimeHandler(instance, 0); err != nil || got != outbound.Handler(handler) {
		t.Fatal("wrong runtime identity", err)
	}
	if err := scope.RegisterRuntime(&memoryHandler{}); err == nil {
		t.Fatal("post-seal registration accepted")
	}
	if err := owner.SealNativeDNSRuntime(instance, manager); err == nil {
		t.Fatal("second seal accepted")
	}
	_ = owner.Close()
	if _, _, err := owner.NativeDNSRuntimeHandler(instance, 0); !errors.Is(err, internet.ErrNativeDNSClosed) {
		t.Fatal(err)
	}
}

func TestNativeDNSConcurrentCloseAndDispatchAdmission(t *testing.T) {
	resolver, ctx := resolverFixture(t, time.Second, &memoryHandler{allowed: true, run: func(ctx context.Context, _ *transport.Link) { <-ctx.Done() }})
	var workers sync.WaitGroup
	for index := 0; index < 12; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if link, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination); err == nil {
				link.Reader.(*policyReader).Interrupt()
			}
		}()
	}
	if err := resolver.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if _, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestNativeDNSNoncooperativeHandlerHasBoundedExplicitDrainFailure(t *testing.T) {
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	resolver, ctx := resolverFixture(t, 5*time.Second, &memoryHandler{allowed: true, run: func(context.Context, *transport.Link) {
		close(entered)
		<-release // deliberately ignores cancellation; never a real worker
		close(ended)
	}})
	if _, err := resolver.dispatcher.Dispatch(ctx, resolver.dispatcher.destination); err != nil {
		t.Fatal(err)
	}
	wait(t, entered)
	started := time.Now()
	if err := resolver.Close(); !errors.Is(err, ErrDrain) {
		t.Fatalf("missing drain failure: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("Close exceeded its native drain bound")
	}
	unblock()
	wait(t, ended)
	if err := resolver.Close(); err != nil {
		t.Fatal("released worker did not drain", err)
	}
}

func TestNativeDNSSameNameLookupsOwnIndependentActualTCPQueries(t *testing.T) {
	for _, cancelFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel-first", false: "second-deadline"}[cancelFirst], func(t *testing.T) {
			entered := make(chan context.Context, 2)
			replyGate := make(chan struct{})
			handler := &memoryHandler{allowed: true, run: func(ctx context.Context, link *transport.Link) {
				reader := &buf.BufferedReader{Reader: link.Reader}
				var length uint16
				if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
					return
				}
				packet := make([]byte, length)
				if _, err := io.ReadFull(reader, packet); err != nil {
					return
				}
				query := &wireDNS.Msg{}
				if err := query.Unpack(packet); err != nil {
					t.Error(err)
					return
				}
				entered <- ctx
				select {
				case <-ctx.Done():
					return
				case <-replyGate:
				}
				response := &wireDNS.Msg{}
				response.SetReply(query)
				response.Answer = []wireDNS.RR{&wireDNS.A{Hdr: wireDNS.RR_Header{Name: query.Question[0].Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 17}, A: net.ParseIP("192.0.2.77")}}
				data, err := response.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				framed := make([]byte, 2, len(data)+2)
				binary.BigEndian.PutUint16(framed, uint16(len(data)))
				framed = append(framed, data...)
				_ = link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, framed))
			}}
			resolver, ctx := resolverFixture(t, time.Second, handler)
			first, cancelFirstContext := context.WithCancel(ctx)
			defer cancelFirstContext()
			secondTimeout := 150 * time.Millisecond
			if cancelFirst {
				secondTimeout = 2 * time.Second
			}
			second, cancelSecondContext := context.WithTimeout(ctx, secondTimeout)
			defer cancelSecondContext()
			results := []chan error{make(chan error, 1), make(chan error, 1)}
			lookup := func(index int, ctx context.Context) {
				ips, _, err := resolver.LookupIPContext(ctx, "same.invalid", dns.IPOption{IPv4Enable: true})
				if err == nil && (len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.77"))) {
					err = errors.New("wrong actual DNS bytes")
				}
				results[index] <- err
			}
			go lookup(0, first)
			var firstHandler, secondHandler context.Context
			select {
			case firstHandler = <-entered:
			case <-time.After(time.Second):
				t.Fatal("first TCP query missing")
			}
			go lookup(1, second)
			select {
			case secondHandler = <-entered:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("same-name request coalesced with another operation")
			}
			canceled, live, canceledHandler := 1, 0, secondHandler
			if cancelFirst {
				canceled, live, canceledHandler = 0, 1, firstHandler
				cancelFirstContext()
			}
			select {
			case err := <-results[canceled]:
				if err == nil {
					t.Fatal("canceled query returned success")
				}
			case <-time.After(400 * time.Millisecond):
				t.Fatal("canceled query waited for unrelated lookup")
			}
			select {
			case <-canceledHandler.Done():
			case <-time.After(100 * time.Millisecond):
				t.Fatal("detached TCP ray lost lookup cancellation")
			}
			select {
			case err := <-results[live]:
				t.Fatal("live request inherited other query completion", err)
			default:
			}
			close(replyGate)
			select {
			case err := <-results[live]:
				if err != nil {
					t.Fatal("independent live query failed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("live query did not receive DNS reply")
			}
		})
	}
}
