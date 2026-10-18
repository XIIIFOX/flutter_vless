// Package nativednsruntime contains an unpublished protected-default DNS seam.
// It does not rewrite caller root DNS or bootstrap transport endpoints.
package nativednsruntime

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

var (
	ErrNotReady = errors.New("native default DNS is not ready")
	ErrClosed   = errors.New("native default DNS is closed")
	ErrPolicy   = errors.New("native default DNS policy is unavailable")
	ErrDrain    = errors.New("native default DNS worker did not drain")
)

type policyEgress interface{ NativeDNSPolicyEgressAllowed() bool }

// TCPResolver is a ready-once delegate installed before Core.New. Bind may run
// only after the same owner's exact runtime handlers have been sealed. Numeric
// resolver + simple direct egress is the first preview policy; no OS fallback.
type TCPResolver struct {
	mu         sync.Mutex
	newServer  func(context.Context) (appdns.Server, error)
	instance   *core.Instance
	closed     bool
	dispatcher *policyDispatcher
}

func NewTCPResolver(owner *internet.NativeDNSOwner, sourceIndex int, destination net.Destination, timeout time.Duration) (*TCPResolver, error) {
	if owner == nil || sourceIndex < 0 || destination.Network != net.Network_TCP || destination.Address == nil ||
		!destination.Address.Family().IsIP() || destination.Port == 0 || timeout <= 0 || timeout > 10*time.Second {
		return nil, ErrPolicy
	}
	// Address implementations expose mutable IP slices. Freeze a separate value.
	destination.Address = net.ParseAddress(destination.Address.IP().String())
	return &TCPResolver{dispatcher: &policyDispatcher{owner: owner, sourceIndex: sourceIndex,
		destination: destination, timeout: timeout, rays: make(map[*policyRay]bool)}}, nil
}

func (r *TCPResolver) Bind(instance *core.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.newServer != nil {
		return ErrPolicy
	}
	handler, _, err := r.dispatcher.owner.NativeDNSRuntimeHandler(instance, r.dispatcher.sourceIndex)
	if err != nil {
		return err
	}
	allowed, ok := handler.(policyEgress)
	if !ok || !allowed.NativeDNSPolicyEgressAllowed() {
		return ErrPolicy
	}
	endpoint := &url.URL{Scheme: "tcp", Host: r.dispatcher.destination.NetAddr()}
	newServer := func(query context.Context) (appdns.Server, error) {
		return appdns.NewTCPNameServer(endpoint, &queryDispatcher{base: r.dispatcher, query: query}, true, false, 0, nil)
	}
	r.instance, r.newServer = instance, newServer
	return nil
}

func (r *TCPResolver) LookupIPContext(ctx context.Context, name string, option dns.IPOption) ([]net.IP, uint32, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, 0, ErrClosed
	}
	newServer, instance := r.newServer, r.instance
	r.mu.Unlock()
	if newServer == nil {
		return nil, 0, ErrNotReady
	}
	if core.FromContext(ctx) != instance {
		return nil, 0, internet.ErrNativeDNSIdentity
	}
	operation, release, _, err := r.dispatcher.owner.NativeDNSRuntimeOperation(ctx, instance, r.dispatcher.sourceIndex)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	operation, cancel := context.WithTimeout(operation, r.dispatcher.timeout)
	defer cancel()
	// Cache-disabled Core servers still coalesce synchronous same-name queries
	// with the first caller's context. A fresh native policy server per lookup
	// keeps request cancellation independent and owns no reusable pool/timer.
	server, err := newServer(operation)
	if err != nil {
		return nil, 0, ErrPolicy
	}
	ips, ttl, err := server.QueryIP(operation, name, option)
	if operation.Err() != nil {
		return nil, 0, operation.Err()
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, 0, ErrClosed
	}
	if _, _, scopeErr := r.dispatcher.owner.NativeDNSRuntimeHandler(instance, r.dispatcher.sourceIndex); scopeErr != nil {
		return nil, 0, scopeErr
	}
	if err != nil {
		return nil, ttl, err
	}
	result := make([]net.IP, len(ips))
	for index, ip := range ips {
		result[index] = append(net.IP(nil), ip...)
	}
	return result, ttl, nil
}

func (r *TCPResolver) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.dispatcher.Close()
}

// The private dispatcher bypasses ordinary routing only for the explicit native
// default policy. It cannot be installed as an instance-wide dispatcher feature.
type policyDispatcher struct {
	mu          sync.Mutex
	owner       *internet.NativeDNSOwner
	sourceIndex int
	destination net.Destination
	timeout     time.Duration
	closed      bool
	rays        map[*policyRay]bool
}

func (*policyDispatcher) Type() any { return routing.DispatcherType() }
func (d *policyDispatcher) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	return nil
}

func (d *policyDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if destination.Network != d.destination.Network || destination.Port != d.destination.Port || destination.Address == nil ||
		!destination.Address.Family().IsIP() || !destination.Address.IP().Equal(d.destination.Address.IP()) {
		return nil, ErrPolicy
	}
	instance := core.FromContext(ctx)
	handler, scope, err := d.owner.NativeDNSRuntimeHandler(instance, d.sourceIndex)
	if err != nil {
		return nil, err
	}
	allowed, ok := handler.(policyEgress)
	if !ok || !allowed.NativeDNSPolicyEgressAllowed() {
		return nil, ErrPolicy
	}
	if _, err := scope.Context(ctx, false); err != nil {
		return nil, err
	}
	// toDnsContext drops owner/cancellation. Restore fixed ownership after it,
	// using fresh request metadata; caller user/Outbounds/Content are not reused.
	base := core.ToBackgroundDetachedContext(ctx)
	operation, release, handler, err := d.owner.NativeDNSRuntimeOperation(base, instance, d.sourceIndex)
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(operation, d.timeout)
	stopCaller := context.AfterFunc(ctx, cancel)
	if ctx.Err() != nil {
		stopCaller()
		cancel()
		release()
		return nil, ctx.Err()
	}
	operation = session.ContextWithInbound(operation, &session.Inbound{Name: "native-default-dns"})
	operation = session.ContextWithContent(operation, &session.Content{Protocol: "dns", SkipDNSResolve: true})
	operation = session.ContextWithOutbounds(operation, []*session.Outbound{{OriginalTarget: d.destination, Target: d.destination, Tag: handler.Tag()}})
	upReader, upWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	downReader, downWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	ray := &policyRay{dispatcher: d, ctx: operation, cancel: func() { stopCaller(); cancel(); release() },
		upReader: upReader, upWriter: upWriter, downReader: downReader, downWriter: downWriter, done: make(chan struct{})}
	d.mu.Lock()
	if d.closed || operation.Err() != nil {
		d.mu.Unlock()
		ray.interrupt()
		return nil, ErrClosed
	}
	d.rays[ray] = true
	ray.stop = context.AfterFunc(operation, ray.interrupt)
	d.mu.Unlock()
	go func() {
		defer ray.finished()
		if operation.Err() != nil {
			return
		}
		handler.Dispatch(operation, &transport.Link{Reader: upReader, Writer: downWriter})
		// Preserve buffered replies; the reader/connection or deadline owns the
		// final interruption. Prematurely interrupting discards a valid DNS reply.
		_ = downWriter.Close()
		upReader.Interrupt()
	}()
	return &transport.Link{Reader: &policyReader{Reader: downReader, ray: ray}, Writer: &policyWriter{Writer: upWriter, ray: ray}}, nil
}

func (*policyDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	if link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	return ErrPolicy
}

func (d *policyDispatcher) Close() error {
	d.mu.Lock()
	d.closed = true
	rays := make([]*policyRay, 0, len(d.rays))
	for ray := range d.rays {
		rays = append(rays, ray)
	}
	d.mu.Unlock()
	for _, ray := range rays {
		ray.interrupt()
	}
	// Interruption is synchronous. Worker drain is bounded and reports failure
	// explicitly; Core.Close remains mandatory for the enclosing instance.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for _, ray := range rays {
		select {
		case <-ray.done:
		case <-timer.C:
			return ErrDrain
		}
	}
	return nil
}

type policyRay struct {
	dispatcher           *policyDispatcher
	ctx                  context.Context
	cancel               func()
	stop                 func() bool
	once                 sync.Once
	upReader, downReader *pipe.Reader
	upWriter, downWriter *pipe.Writer
	done                 chan struct{}
	interrupted, ended   bool // guarded by dispatcher.mu
}

func (ray *policyRay) interrupt() {
	ray.once.Do(func() {
		ray.cancel()
		ray.upReader.Interrupt()
		ray.upWriter.Interrupt()
		ray.downReader.Interrupt()
		ray.downWriter.Interrupt()
		d := ray.dispatcher
		d.mu.Lock()
		ray.interrupted = true
		if ray.stop != nil {
			ray.stop()
		}
		if ray.ended {
			delete(d.rays, ray)
		}
		d.mu.Unlock()
	})
}

func (ray *policyRay) finished() {
	d := ray.dispatcher
	d.mu.Lock()
	ray.ended = true
	if ray.interrupted {
		delete(d.rays, ray)
	}
	close(ray.done)
	d.mu.Unlock()
}

type policyReader struct {
	*pipe.Reader
	ray *policyRay
}

func (reader *policyReader) Interrupt() { reader.ray.interrupt() }
func (reader *policyReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := reader.Reader.ReadMultiBuffer()
	if err != nil {
		reader.ray.interrupt()
	}
	return mb, err
}

type policyWriter struct {
	*pipe.Writer
	ray *policyRay
}

func (writer *policyWriter) Interrupt()   { writer.ray.interrupt() }
func (writer *policyWriter) Close() error { writer.ray.interrupt(); return nil }

var _ dns.NativeLocalResolver = (*TCPResolver)(nil)
var _ routing.Dispatcher = (*policyDispatcher)(nil)

// One query, one dispatcher wrapper: Core's toDnsContext deliberately detaches
// the supplied context, so reattach this lookup's operation after that helper.
// This object is never cached/shared with a subsequent DNS lookup.
type queryDispatcher struct {
	base  *policyDispatcher
	query context.Context
}

func (*queryDispatcher) Type() any      { return routing.DispatcherType() }
func (q *queryDispatcher) Start() error { return q.query.Err() }
func (*queryDispatcher) Close() error   { return nil }
func (q *queryDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if core.FromContext(ctx) != core.FromContext(q.query) {
		return nil, internet.ErrNativeDNSIdentity
	}
	return q.base.Dispatch(q.query, destination)
}
func (q *queryDispatcher) DispatchLink(ctx context.Context, destination net.Destination, link *transport.Link) error {
	return q.base.DispatchLink(ctx, destination, link)
}
