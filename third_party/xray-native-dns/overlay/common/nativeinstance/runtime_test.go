package nativeinstance

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/nativednsruntime"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type fakeCore struct {
	mu       sync.Mutex
	stages   []string
	sealFn   func(*internet.NativeDNSOwner) error
	bindFn   func(*nativednsruntime.TCPResolver) error
	startFn  func() error
	closeFn  func() error
	lookupFn func(string) ([]xnet.IP, error)
	closes   atomic.Int32
	queries  atomic.Int32
}

func (f *fakeCore) record(stage string) {
	f.mu.Lock()
	f.stages = append(f.stages, stage)
	f.mu.Unlock()
}
func (f *fakeCore) seal(o *internet.NativeDNSOwner) error {
	f.record("seal")
	if f.sealFn != nil {
		return f.sealFn(o)
	}
	return nil
}
func (f *fakeCore) bind(r *nativednsruntime.TCPResolver) error {
	f.record("bind")
	if f.bindFn != nil {
		return f.bindFn(r)
	}
	return nil
}
func (f *fakeCore) start() error {
	f.record("start")
	if f.startFn != nil {
		return f.startFn()
	}
	return nil
}
func (f *fakeCore) close() error {
	f.record("close")
	f.closes.Add(1)
	if f.closeFn != nil {
		return f.closeFn()
	}
	return nil
}
func (f *fakeCore) lookup(n string) ([]xnet.IP, error) {
	f.queries.Add(1)
	if f.lookupFn != nil {
		return f.lookupFn(n)
	}
	return []xnet.IP{{127, 0, 0, 1}}, nil
}
func (f *fakeCore) lookupDNS(name string) ([]xnet.IP, uint32, error) {
	ips, err := f.lookup(name)
	return ips, 37, err
}

func fakeFactory(f *fakeCore) coreFactory {
	return func(context.Context, *core.Config) (runtimeCore, error) { return f, nil }
}
func closedOwner(t *testing.T, o *internet.NativeDNSOwner) {
	t.Helper()
	if !errors.Is(o.SealNativeDNSRuntime(nil, nil), internet.ErrNativeDNSClosed) {
		t.Fatal("owner not synchronously revoked")
	}
}
func closeRuntime(t *testing.T, r *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func await(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("controlled operation did not complete")
	}
}

func TestNativeInstanceStartOrdersFreshOwnerBindingsAndClones(t *testing.T) {
	p := mustPrepared(t)
	f := &fakeCore{}
	var receivedA, receivedB *core.Config
	factory := func(ctx context.Context, c *core.Config) (runtimeCore, error) {
		if delegate, present := featuredns.NativeLocalResolverFromContext(ctx); !present || delegate == nil {
			t.Fatal("delegate not installed before constructor")
		}
		if receivedA == nil {
			receivedA = c
		} else {
			receivedB = c
		}
		return &fakeCore{}, nil
	}
	a, err := p.start(context.Background(), factory)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.start(context.Background(), factory)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, a)
	defer closeRuntime(t, b)
	if a.owner == b.owner || a.resolver == b.resolver || receivedA == receivedB || receivedA.Outbound[0] == receivedB.Outbound[0] {
		t.Fatal("runtime ownership reused")
	}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	closeRuntime(t, r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.stages) != 4 || f.stages[0] != "seal" || f.stages[1] != "bind" || f.stages[2] != "start" || f.stages[3] != "close" {
		t.Fatal("wrong stage order", f.stages)
	}
}

func TestNativeInstanceCandidateFailuresDoNotCloseAcceptedRuntime(t *testing.T) {
	p := mustPrepared(t)
	accepted := &fakeCore{}
	a, err := p.start(context.Background(), fakeFactory(accepted))
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, a)
	for _, stage := range []string{"new", "seal", "bind", "start"} {
		t.Run(stage, func(t *testing.T) {
			candidate := &fakeCore{}
			privateFailure := errors.New("private-credential-canary")
			factory := fakeFactory(candidate)
			switch stage {
			case "new":
				factory = func(context.Context, *core.Config) (runtimeCore, error) { return candidate, privateFailure }
			case "seal":
				candidate.sealFn = func(*internet.NativeDNSOwner) error { return privateFailure }
			case "bind":
				candidate.bindFn = func(*nativednsruntime.TCPResolver) error { return privateFailure }
			case "start":
				candidate.startFn = func() error { return privateFailure }
			}
			if result, err := p.start(context.Background(), factory); result != nil || !errors.Is(err, ErrStart) {
				t.Fatal("candidate failure published")
			}
			if candidate.closes.Load() != 1 || accepted.closes.Load() != 0 {
				t.Fatal("wrong runtime closed")
			}
			if ips, err := a.LookupIPv4(context.Background(), "caller.invalid"); err != nil || len(ips) != 1 {
				t.Fatal("accepted runtime no longer works")
			}
		})
	}
}

func TestNativeInstanceCancellationDuringConstructorClosesLateCore(t *testing.T) {
	p := mustPrepared(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	candidate := &fakeCore{}
	var result *Runtime
	var failure error
	go func() {
		defer close(ended)
		result, failure = p.start(ctx, func(context.Context, *core.Config) (runtimeCore, error) {
			close(entered)
			<-release
			return candidate, nil
		})
	}()
	await(t, entered)
	cancel()
	close(release)
	await(t, ended)
	if result != nil || !errors.Is(failure, ErrStart) || candidate.closes.Load() != 1 {
		t.Fatal("late cancelled constructor escaped cleanup")
	}
	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	if len(candidate.stages) != 1 || candidate.stages[0] != "close" {
		t.Fatal("cancelled candidate advanced startup", candidate.stages)
	}
}

func TestNativeInstanceCancellationAtEveryStartHandoff(t *testing.T) {
	for _, stage := range []string{"seal", "bind", "start"} {
		t.Run(stage, func(t *testing.T) {
			p := mustPrepared(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeCore{}
			switch stage {
			case "seal":
				f.sealFn = func(*internet.NativeDNSOwner) error { cancel(); return nil }
			case "bind":
				f.bindFn = func(*nativednsruntime.TCPResolver) error { cancel(); return nil }
			case "start":
				f.startFn = func() error { cancel(); return nil }
			}
			if r, err := p.start(ctx, fakeFactory(f)); r != nil || !errors.Is(err, ErrStart) || f.closes.Load() != 1 {
				t.Fatal("stale startup published")
			}
		})
	}
}

func TestNativeInstanceCancelledCloseRevokesAndRetainsCleanup(t *testing.T) {
	p := mustPrepared(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f := &fakeCore{closeFn: func() error { close(entered); <-release; return nil }}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(r.Close(ctx), ErrDrain) {
		t.Fatal("cancelled wait did not report pending cleanup")
	}
	closedOwner(t, r.owner)
	await(t, entered)
	if _, err := r.LookupIPv4(context.Background(), "late.invalid"); !errors.Is(err, ErrClosed) {
		t.Fatal("post-close query accepted")
	}
	close(release)
	closeRuntime(t, r)
	closeRuntime(t, r)
	if f.closes.Load() != 1 {
		t.Fatal("cleanup repeated")
	}
}

func TestNativeInstanceParentCancellationRevokesBackgroundQueries(t *testing.T) {
	p := mustPrepared(t)
	parent, cancel := context.WithCancel(context.Background())
	r, err := p.start(parent, fakeFactory(&fakeCore{}))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	closeRuntime(t, r)
	closedOwner(t, r.owner)
	if _, err := r.LookupIPv4(context.Background(), "late.invalid"); !errors.Is(err, ErrClosed) {
		t.Fatal("parent cancellation ignored")
	}
}

func TestNativeInstanceLookupOutstandingWorkerIsBoundedAndCloseReportsIt(t *testing.T) {
	p := mustPrepared(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { close(entered); <-release; return []xnet.IP{{127, 0, 0, 1}}, nil }}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	query, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	var failure error
	go func() { defer close(ended); _, failure = r.LookupIPv4(query, "caller.invalid") }()
	await(t, entered)
	cancel()
	await(t, ended)
	if !errors.Is(failure, context.Canceled) {
		t.Fatal("caller cancellation not reported")
	}
	for i := 0; i < 32; i++ {
		if _, err := r.LookupIPv4(context.Background(), "other.invalid"); !errors.Is(err, ErrBusy) {
			t.Fatal("cancelled worker capacity was not retained")
		}
	}
	if f.queries.Load() != 1 {
		t.Fatal("unbounded lookup goroutines created")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer closeCancel()
	if !errors.Is(r.Close(closeCtx), ErrDrain) {
		t.Fatal("outstanding root query falsely drained")
	}
	close(release)
	closeRuntime(t, r)
	if f.closes.Load() != 1 {
		t.Fatal("Core cleanup not owned once")
	}
}

func TestNativeInstanceLookupDeadlineLateResultAndOutputCopy(t *testing.T) {
	p := mustPrepared(t)
	p.policy.LookupTimeout = 10 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	raw := []xnet.IP{{127, 0, 0, 1}}
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { close(entered); <-release; return raw, nil }}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	var failure error
	go func() { defer close(ended); _, failure = r.LookupIPv4(context.Background(), "caller.invalid") }()
	await(t, entered)
	await(t, ended)
	if !errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("lookup bound ignored")
	}
	close(release)
	closeRuntime(t, r)
	// A fresh runtime proves copied root results are safe value types.
	f2 := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { return raw, nil }}
	b, err := p.start(context.Background(), fakeFactory(f2))
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, b)
	ips, err := b.LookupIPv4(context.Background(), "caller.invalid")
	if err != nil {
		t.Fatal(err)
	}
	raw[0][0] = 9
	if len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatal("root mutable reply escaped")
	}
}

func TestNativeInstanceLookupInputAndPrivateFailures(t *testing.T) {
	p := mustPrepared(t)
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { return nil, errors.New("private-runtime-secret") }}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, r)
	for _, name := range []string{"", " ", "_srv.invalid", "name..invalid", "-label.invalid", "label-.invalid", "💡.invalid"} {
		if _, err := r.LookupIPv4(context.Background(), name); !errors.Is(err, ErrLookup) {
			t.Fatal("unqualified query accepted")
		}
	}
	if f.queries.Load() != 0 {
		t.Fatal("invalid query entered root DNS")
	}
	if _, err := r.LookupIPv4(context.Background(), "caller.invalid"); err != ErrLookup {
		t.Fatal("private root error exported")
	}
}

func TestNativeInstanceCloseErrorRemainsClosedVocabulary(t *testing.T) {
	p := mustPrepared(t)
	f := &fakeCore{closeFn: func() error { return errors.New("private-core-close-secret") }}
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Close(context.Background()), ErrDrain) || !errors.Is(r.Close(context.Background()), ErrDrain) || f.closes.Load() != 1 {
		t.Fatal("cleanup failure lost or repeated")
	}
}

// A custom context observes the actual commit's lock boundary, not a mirrored
// lifecycle model. The commit must never consult cancellation outside that lock.
type commitContext struct {
	context.Context
	runtime *Runtime
	outside atomic.Bool
}

func (c *commitContext) Err() error {
	if c.runtime.mu.TryLock() {
		c.outside.Store(true)
		c.runtime.mu.Unlock()
	}
	return c.Context.Err()
}
func TestNativeInstanceLookupCommitChecksCancellationUnderAdmission(t *testing.T) {
	p := mustPrepared(t)
	r, err := p.start(context.Background(), fakeFactory(&fakeCore{}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, r)
	operation := &commitContext{Context: context.Background(), runtime: r}
	if _, err := r.commitLookup(operation, lookupResult{ips: []xnet.IP{{127, 0, 0, 1}}}); err != nil || operation.outside.Load() {
		t.Fatal("publication cancellation check escaped admission lock")
	}
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			r.mu.Lock()
			entered, ended := make(chan struct{}), make(chan struct{})
			var answerErr error
			go func() {
				defer close(ended)
				close(entered)
				_, answerErr = r.commitLookup(ctx, lookupResult{ips: []xnet.IP{{127, 0, 0, 1}}})
			}()
			await(t, entered)
			if deadline {
				<-ctx.Done()
			} else {
				cancel()
			}
			r.mu.Unlock()
			await(t, ended)
			if !errors.Is(answerErr, ctx.Err()) {
				t.Fatal("late answer published through cancelled lock wait")
			}
		})
	}
}
