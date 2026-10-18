package nativeinstance

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/nativednsruntime"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

// runtimeCore isolates lifecycle sequencing for pure controlled tests. Tests do
// not replace global constructors or create a real Core/listener/resolver.
type runtimeCore interface {
	seal(*internet.NativeDNSOwner) error
	bind(*nativednsruntime.TCPResolver) error
	start() error
	close() error
	lookupDNS(string) ([]xnet.IP, uint32, error)
}
type coreFactory func(context.Context, *core.Config) (runtimeCore, error)

type liveCore struct{ instance *core.Instance }

func (c *liveCore) seal(owner *internet.NativeDNSOwner) error {
	manager, ok := c.instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok || manager == nil {
		return ErrStart
	}
	return owner.SealNativeDNSRuntime(c.instance, manager)
}
func (c *liveCore) bind(resolver *nativednsruntime.TCPResolver) error {
	return resolver.Bind(c.instance)
}
func (c *liveCore) start() error { return c.instance.Start() }
func (c *liveCore) close() error { return c.instance.Close() }
func (c *liveCore) lookupDNS(name string) ([]xnet.IP, uint32, error) {
	client, ok := c.instance.GetFeature(featuredns.ClientType()).(featuredns.Client)
	if !ok || client == nil {
		return nil, 0, ErrLookup
	}
	return client.LookupIP(name, featuredns.IPOption{IPv4Enable: true})
}
func construct(ctx context.Context, c *core.Config) (runtimeCore, error) {
	instance, err := core.NewWithContext(ctx, c)
	if instance == nil {
		return nil, err
	}
	return &liveCore{instance}, err
}

// Runtime owns a single Core and all its private resolver/lookup work. Close is
// one-shot and always revokes before waiting. A bounded return never transfers
// cleanup ownership to the caller: an unfinished cleanup remains owned here.
// There is no Stats API in this preview.
type Runtime struct {
	mu           sync.Mutex
	closed       bool
	core         runtimeCore
	owner        *internet.NativeDNSOwner
	resolver     *nativednsruntime.TCPResolver
	life         context.Context
	cancel       context.CancelFunc
	buildDone    chan struct{}
	cleanupOnce  sync.Once
	cleanupDone  chan struct{}
	cleanupError error
	workers      sync.WaitGroup
	slot         chan struct{}
	timeout      time.Duration
	bridge       *systemDNSBinding
}

func (p *Prepared) Start(ctx context.Context) (*Runtime, error) { return p.start(ctx, construct) }
func (p *Prepared) start(ctx context.Context, factory coreFactory) (result *Runtime, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrStart
	}
	configuration, bindings, err := p.clone()
	if err != nil {
		return nil, err
	}
	owner, err := internet.NewNativeDNSOwner(bindings)
	if err != nil {
		return nil, ErrStart
	}
	resolver, err := nativednsruntime.NewTCPResolver(owner, p.policy.DefaultOutboundIndex, resolverDestination(p.policy), p.policy.LookupTimeout)
	if err != nil {
		_ = owner.Close()
		return nil, ErrStart
	}
	life, cancel := context.WithCancel(ctx)
	r := &Runtime{owner: owner, resolver: resolver, life: life, cancel: cancel, buildDone: make(chan struct{}), cleanupDone: make(chan struct{}), slot: make(chan struct{}, 1), timeout: p.policy.LookupTimeout}
	if p.policy.SystemDNSBridge != nil {
		r.bridge = &systemDNSBinding{identity: configuration, owner: owner, virtual: p.policy.SystemDNSBridge.VirtualIPv4}
	}
	// The callback revokes while construction may still be blocked. Cleanup waits
	// for buildDone so a Core returned late is still closed exactly once.
	context.AfterFunc(life, func() { r.beginClose() })
	defer func() {
		close(r.buildDone)
		if failure != nil {
			r.beginClose()
			wait, cancel := context.WithTimeout(context.Background(), closeWait)
			defer cancel()
			_ = r.waitClose(wait)
		}
	}()
	scoped := featuredns.ContextWithNativeLocalResolver(internet.ContextWithNativeDNSOwner(life, owner), resolver)
	instance, err := factory(scoped, configuration)
	r.mu.Lock()
	r.core = instance
	admitted := !r.closed && life.Err() == nil
	r.mu.Unlock()
	if err != nil || instance == nil || !admitted {
		return nil, ErrStart
	}
	if instance.seal(owner) != nil || !r.current() {
		return nil, ErrStart
	}
	if instance.bind(resolver) != nil || !r.current() {
		return nil, ErrStart
	}
	if instance.start() != nil {
		return nil, ErrStart
	}
	r.mu.Lock()
	if r.closed || life.Err() != nil {
		r.mu.Unlock()
		return nil, ErrStart
	}
	result = r // Final handoff rejects already observed cancellation/revocation.
	r.mu.Unlock()
	return result, nil
}

func (r *Runtime) current() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.life.Err() == nil
}
func (r *Runtime) beginClose() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	// Never hold state locks across delegate/Core shutdown or user callbacks.
	r.cancel()
	_ = r.owner.Close() // Synchronous admission/lifetime revocation even on ctx cancellation.
	r.cleanupOnce.Do(func() {
		go func() {
			<-r.buildDone
			failed := r.resolver.Close() != nil
			r.mu.Lock()
			instance := r.core
			r.mu.Unlock()
			if instance != nil && instance.close() != nil {
				failed = true
			}
			r.workers.Wait()
			r.mu.Lock()
			if failed {
				r.cleanupError = ErrDrain
			}
			r.mu.Unlock()
			close(r.cleanupDone)
		}()
	})
}
func (r *Runtime) waitClose(ctx context.Context) error {
	select {
	case <-r.cleanupDone:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.cleanupError
	default:
	}
	select {
	case <-r.cleanupDone:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.cleanupError
	case <-ctx.Done():
		return ErrDrain
	}
}
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.beginClose()
	if ctx == nil {
		ctx = context.Background()
	}
	wait, cancel := context.WithTimeout(ctx, closeWait)
	defer cancel()
	return r.waitClose(wait)
}

type lookupResult struct {
	ips []xnet.IP
	ttl uint32
	err error
}

// LookupIPv4 uses this instance's caller root DNS (including hosts/per-domain
// rules), never a direct delegate shortcut. The pinned root API is context-free:
// cancellation bounds waiting, not immediate remote exchange cancellation.
// At most ONE worker remains outstanding per Runtime. A cancelled/timed-out
// caller cannot spawn unbounded background work; Close waits for the worker and
// reports ErrDrain if it cannot finish within the caller's bounded wait.
func (r *Runtime) LookupIPv4(ctx context.Context, name string) ([]netip.Addr, error) {
	if r == nil || ctx == nil {
		return nil, ErrClosed
	}
	operation, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	answer, err := r.lookupRoot(operation, name)
	if err != nil {
		return nil, err
	}
	return r.commitLookup(operation, answer)
}

// lookupRoot is the only worker-admission path used by both the plain lookup
// API and the optional wire primitive. The caller owns an already bounded
// operation context and must recheck it at final result publication.
func (r *Runtime) lookupRoot(operation context.Context, name string) (lookupResult, error) {
	if r == nil || operation == nil {
		return lookupResult{}, ErrClosed
	}
	if !validLookupName(name) {
		return lookupResult{}, ErrLookup
	}
	if err := operation.Err(); err != nil {
		return lookupResult{}, err
	}
	r.mu.Lock()
	if r.closed || r.life.Err() != nil || r.core == nil {
		r.mu.Unlock()
		return lookupResult{}, ErrClosed
	}
	select {
	case r.slot <- struct{}{}:
	default:
		r.mu.Unlock()
		return lookupResult{}, ErrBusy
	}
	r.workers.Add(1)
	instance := r.core
	r.mu.Unlock()
	result := make(chan lookupResult, 1)
	go func() {
		defer r.workers.Done()
		defer func() { <-r.slot }()
		ips, ttl, err := instance.lookupDNS(name)
		copied := make([]xnet.IP, len(ips))
		for i, ip := range ips {
			copied[i] = append(xnet.IP(nil), ip...)
		}
		result <- lookupResult{ips: copied, ttl: ttl, err: err}
	}()
	select {
	case <-r.life.Done():
		return lookupResult{}, ErrClosed
	case <-operation.Done():
		return lookupResult{}, operation.Err()
	case answer := <-result:
		return answer, nil
	}
}

// Commit checks caller cancellation under the same lock as runtime admission.
// A result waiting for that lock cannot publish after cancellation observed at
// this final handoff. Context cancellation after the handoff remains concurrent.
func (r *Runtime) commitLookup(operation context.Context, answer lookupResult) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.life.Err() != nil {
		return nil, ErrClosed
	}
	if err := operation.Err(); err != nil {
		return nil, err
	}
	if answer.err != nil {
		return nil, ErrLookup
	}
	output := make([]netip.Addr, 0, len(answer.ips))
	for _, ip := range answer.ips {
		value, ok := netip.AddrFromSlice(ip)
		if !ok || !value.Unmap().Is4() {
			return nil, ErrLookup
		}
		output = append(output, value.Unmap())
	}
	if len(output) == 0 {
		return nil, ErrLookup
	}
	// Keep the cancellation observation adjacent to final successful publication,
	// after even the (bounded) result-copy/conversion work.
	if err := operation.Err(); err != nil {
		return nil, err
	}
	return output, nil
}

// Strict ASCII DNS labels are a preview constraint. IDNA, underscores, special
// localhost/+local/FakeDNS query semantics remain separately unqualified.
func validLookupName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.TrimSpace(name) != name {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
