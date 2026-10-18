package nativeinstance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

func bridgePolicy() Policy {
	p := testPolicy()
	p.SystemDNSBridge = &SystemDNSBridgePolicy{VirtualIPv4: netip.MustParseAddr("198.18.0.53")}
	return p
}
func bridgePrepared(t *testing.T) *Prepared {
	t.Helper()
	p, err := PrepareJSON(testSource(), bridgePolicy())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func bridgeRuntime(t *testing.T, p *Prepared, f *fakeCore) (*Runtime, *SystemDNSBridge) {
	t.Helper()
	r, err := p.start(context.Background(), fakeFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeRuntime(t, r) })
	b, err := r.SystemDNSBridge()
	if err != nil {
		t.Fatal(err)
	}
	return r, b
}
func bridgeDestination() netip.AddrPort { return netip.MustParseAddrPort("198.18.0.53:53") }
func bridgeQuery(t *testing.T, kind dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("Caller.Invalid.")
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1462, RecursionDesired: true})
	if builder.StartQuestions() != nil || builder.Question(dnsmessage.Question{Name: name, Type: kind, Class: dnsmessage.ClassINET}) != nil {
		t.Fatal("query build failed")
	}
	packet, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func bridgeFrame(packet []byte) []byte {
	out := make([]byte, len(packet)+2)
	binary.BigEndian.PutUint16(out, uint16(len(packet)))
	copy(out[2:], packet)
	return out
}
func bridgeResponse(t *testing.T, packet []byte, tcp bool) dnsmessage.Message {
	t.Helper()
	if tcp {
		if len(packet) < 2 || int(binary.BigEndian.Uint16(packet[:2])) != len(packet)-2 {
			t.Fatal("bad response frame")
		}
		packet = packet[2:]
	}
	var response dnsmessage.Message
	if response.Unpack(packet) != nil {
		t.Fatal("bad response")
	}
	return response
}

func TestNativeSystemDNSBridgePolicyCopyAndNoCompiledTransform(t *testing.T) {
	policy := bridgePolicy()
	p, err := PrepareJSON(testSource(), policy)
	if err != nil {
		t.Fatal(err)
	}
	plain := mustPrepared(t)
	if !proto.Equal(p.blueprint, plain.blueprint) || !bytes.Equal(p.normalized, plain.normalized) || !bytes.Equal(p.source, plain.source) || p.SourceDigest() != plain.SourceDigest() {
		t.Fatal("bridge rewrote caller source/compiled graph")
	}
	policy.SystemDNSBridge.VirtualIPv4 = netip.MustParseAddr("198.18.0.99")
	_, b := bridgeRuntime(t, p, &fakeCore{})
	if b.binding.virtual != bridgePolicy().SystemDNSBridge.VirtualIPv4 {
		t.Fatal("caller-owned policy mutated prepared binding")
	}
	for _, value := range []string{"0.0.0.0", "224.0.0.1", "127.0.0.1", "::1", "::ffff:198.18.0.53"} {
		p := bridgePolicy()
		p.SystemDNSBridge.VirtualIPv4 = netip.MustParseAddr(value)
		if _, err := PrepareJSON(testSource(), p); !errors.Is(err, ErrPolicy) {
			t.Fatal("invalid virtual endpoint admitted")
		}
	}
	source := replaceSource(t, func(o map[string]any) { o["systemDNSBridge"] = map[string]any{"virtualIPv4": "198.18.0.53"} })
	ungranted, err := PrepareJSON(source, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	r, err := ungranted.start(context.Background(), fakeFactory(&fakeCore{}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime(t, r)
	if _, err := r.SystemDNSBridge(); !errors.Is(err, ErrUnsupported) {
		t.Fatal("caller JSON granted native bridge")
	}
}

func TestNativeSystemDNSBridgeExactOpaqueOwnerAndDestination(t *testing.T) {
	p := bridgePrepared(t)
	fa, fb := &fakeCore{}, &fakeCore{}
	a, ba := bridgeRuntime(t, p, fa)
	_, bb := bridgeRuntime(t, p, fb)
	query := bridgeQuery(t, dnsmessage.TypeA)
	for _, destination := range []string{"198.18.0.54:53", "198.18.0.53:54", "127.0.0.1:53", "[::ffff:198.18.0.53]:53"} {
		if _, err := ba.ExchangeUDP(context.Background(), netip.MustParseAddrPort(destination), query); err == nil {
			t.Fatal("nonvirtual destination admitted")
		}
	}
	zero := &SystemDNSBridge{}
	if _, err := zero.ExchangeUDP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrClosed) {
		t.Fatal("empty bridge capability admitted")
	}
	foreign := *ba
	foreign.runtime = bb.runtime
	if _, err := foreign.ExchangeUDP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrClosed) {
		t.Fatal("foreign owner binding admitted")
	}
	if fa.queries.Load() != 0 || fb.queries.Load() != 0 {
		t.Fatal("failed authority check entered root DNS")
	}
	closeRuntime(t, a)
	if _, err := ba.ExchangeUDP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrClosed) {
		t.Fatal("closed owner capability admitted")
	}
	if _, err := bb.ExchangeUDP(context.Background(), bridgeDestination(), query); err != nil {
		t.Fatal("closing A broke B")
	}
}

func TestNativeSystemDNSBridgeWireAUsesRootTTLAndPreservesQuestion(t *testing.T) {
	var observed atomic.Int32
	f := &fakeCore{lookupFn: func(name string) ([]xnet.IP, error) {
		if name != "Caller.Invalid." {
			return nil, errors.New("incorrect root query")
		}
		observed.Add(1)
		return []xnet.IP{{127, 0, 0, 7}}, nil
	}}
	_, b := bridgeRuntime(t, bridgePrepared(t), f)
	for _, tcp := range []bool{false, true} {
		query := bridgeQuery(t, dnsmessage.TypeA)
		var packet []byte
		var err error
		if tcp {
			packet, err = b.ExchangeTCP(context.Background(), bridgeDestination(), bridgeFrame(query))
		} else {
			packet, err = b.ExchangeUDP(context.Background(), bridgeDestination(), query)
		}
		if err != nil {
			t.Fatal(err)
		}
		answer := bridgeResponse(t, packet, tcp)
		if answer.ID != 0x1462 || !answer.Response || !answer.RecursionDesired || !answer.RecursionAvailable || answer.Authoritative || answer.AuthenticData || answer.RCode != 0 || len(answer.Questions) != 1 || answer.Questions[0].Name.String() != "Caller.Invalid." || len(answer.Answers) != 1 {
			t.Fatal("wire answer lost source question/header")
		}
		body, ok := answer.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || body.A != [4]byte{127, 0, 0, 7} || answer.Answers[0].Header.TTL != 37 {
			t.Fatal("root address/TTL not preserved")
		}
	}
	if observed.Load() != 2 {
		t.Fatal("wire request bypassed or multiplied root lookups")
	}
}

func TestNativeSystemDNSBridgeAAAAAndNonIPNeverQueryOrRelay(t *testing.T) {
	f := &fakeCore{}
	_, b := bridgeRuntime(t, bridgePrepared(t), f)
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeTXT, dnsmessage.TypePTR, dnsmessage.Type(64), dnsmessage.Type(65)} {
		packet, err := b.ExchangeUDP(context.Background(), bridgeDestination(), bridgeQuery(t, kind))
		if err != nil {
			t.Fatal(err)
		}
		answer := bridgeResponse(t, packet, false)
		expected := dnsmessage.RCodeRefused
		if kind == dnsmessage.TypeAAAA {
			expected = dnsmessage.RCodeSuccess
		}
		if answer.RCode != expected || len(answer.Answers) != 0 || len(answer.Questions) != 1 || answer.Questions[0].Type != kind {
			t.Fatal("incorrect bounded non-A policy")
		}
	}
	if f.queries.Load() != 0 {
		t.Fatal("non-A query reached root/physical resolver")
	}
}

func TestNativeSystemDNSBridgeMalformedAndEDNSRefusedBeforeRoot(t *testing.T) {
	f := &fakeCore{}
	_, b := bridgeRuntime(t, bridgePrepared(t), f)
	good := bridgeQuery(t, dnsmessage.TypeA)
	cases := map[string][]byte{
		"short": {1, 2}, "oversized": make([]byte, 513), "trailing": append(append([]byte(nil), good...), 0),
		"compression": append(append([]byte(nil), good[:12]...), []byte{0xc0, 0x0c, 0, 1, 0, 1}...),
	}
	duplicate := append([]byte(nil), good...)
	duplicate[5] = 2
	cases["multipleQuestion"] = duplicate
	response := append([]byte(nil), good...)
	response[2] |= 0x80
	cases["response"] = response
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := b.ExchangeUDP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrDNSQuery) {
				t.Fatal("malformed request accepted")
			}
		})
	}
	for _, query := range [][]byte{nil, {0}, {0, 1}, {0, 1, 3}, append(bridgeFrame(good), 0)} {
		if _, err := b.ExchangeTCP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrDNSQuery) {
			t.Fatal("malformed TCP frame accepted")
		}
	}
	for _, mutate := range []func([]byte) []byte{
		func(q []byte) []byte { q[11] = 1; return append(q, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0) }, // EDNS OPT
		func(q []byte) []byte { q[2] |= 0x08; return q },                                        // nonstandard opcode
		func(q []byte) []byte { q[len(q)-1] = 3; return q },                                     // non-IN class
		func(q []byte) []byte { q[3] |= 0x40; return q },                                        // reserved header flag
	} {
		query := mutate(append([]byte(nil), good...))
		packet, err := b.ExchangeUDP(context.Background(), bridgeDestination(), query)
		if err != nil {
			t.Fatal(err)
		}
		if answer := bridgeResponse(t, packet, false); answer.RCode != dnsmessage.RCodeRefused || len(answer.Answers) != 0 || answer.OpCode != dnsmessage.OpCode((query[2]>>3)&0x0f) {
			t.Fatal("unsupported wire feature not refused")
		}
	}
	if f.queries.Load() != 0 {
		t.Fatal("invalid/unsupported wire entered root DNS")
	}
}

func TestNativeSystemDNSBridgeRootRCodeAndPrivateErrors(t *testing.T) {
	for _, item := range []struct {
		name string
		err  error
		code dnsmessage.RCode
	}{
		{"empty", featuredns.ErrEmptyResponse, dnsmessage.RCodeSuccess},
		{"NXDOMAIN", featuredns.RCodeError(3), dnsmessage.RCodeNameError},
		{"REFUSED", featuredns.RCodeError(5), dnsmessage.RCodeRefused},
		{"extended", featuredns.RCodeError(99), dnsmessage.RCodeServerFailure},
		{"private", errors.New("private-root-credential-canary"), dnsmessage.RCodeServerFailure},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { return nil, item.err }}
			_, b := bridgeRuntime(t, bridgePrepared(t), f)
			packet, err := b.ExchangeUDP(context.Background(), bridgeDestination(), bridgeQuery(t, dnsmessage.TypeA))
			if err != nil {
				t.Fatal(err)
			}
			answer := bridgeResponse(t, packet, false)
			if answer.RCode != item.code || len(answer.Answers) != 0 || bytes.Contains(packet, []byte("private-root")) {
				t.Fatal("root error escaped or wrong RCode")
			}
		})
	}
}

func TestNativeSystemDNSBridgeUDPTruncationAndBoundedTCP(t *testing.T) {
	ips := make([]xnet.IP, 50)
	for i := range ips {
		ips[i] = xnet.IP{10, 1, 0, byte(i)}
	}
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { return ips, nil }}
	_, b := bridgeRuntime(t, bridgePrepared(t), f)
	query := bridgeQuery(t, dnsmessage.TypeA)
	packet, err := b.ExchangeUDP(context.Background(), bridgeDestination(), query)
	if err != nil {
		t.Fatal(err)
	}
	answer := bridgeResponse(t, packet, false)
	if len(packet) > 512 || !answer.Truncated || len(answer.Answers) != 0 {
		t.Fatal("oversized UDP response not bounded/truncated")
	}
	packet, err = b.ExchangeTCP(context.Background(), bridgeDestination(), bridgeFrame(query))
	if err != nil {
		t.Fatal(err)
	}
	answer = bridgeResponse(t, packet, true)
	if len(packet) > 4098 || answer.Truncated || len(answer.Answers) != 50 {
		t.Fatal("TCP did not preserve bounded full record set")
	}
	ips = make([]xnet.IP, 257)
	for i := range ips {
		ips[i] = xnet.IP{10, 1, 0, byte(i)}
	}
	packet, err = b.ExchangeTCP(context.Background(), bridgeDestination(), bridgeFrame(query))
	if err != nil {
		t.Fatal(err)
	}
	answer = bridgeResponse(t, packet, true)
	if len(packet) > 4098 || answer.RCode != dnsmessage.RCodeServerFailure || len(answer.Answers) != 0 {
		t.Fatal("oversized TCP result falsely succeeded")
	}
}

func TestNativeSystemDNSBridgeSharesOutstandingWorkerAndCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { close(entered); <-release; return []xnet.IP{{127, 0, 0, 1}}, nil }}
	r, b := bridgeRuntime(t, bridgePrepared(t), f)
	query := bridgeQuery(t, dnsmessage.TypeA)
	operation, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	var failure error
	go func() { defer close(ended); _, failure = b.ExchangeUDP(operation, bridgeDestination(), query) }()
	await(t, entered)
	cancel()
	await(t, ended)
	if !errors.Is(failure, context.Canceled) {
		t.Fatal("wire caller cancellation lost")
	}
	if _, err := r.LookupIPv4(context.Background(), "other.invalid"); !errors.Is(err, ErrBusy) {
		t.Fatal("plain lookup bypassed wire worker bound")
	}
	if _, err := b.ExchangeTCP(context.Background(), bridgeDestination(), bridgeFrame(query)); !errors.Is(err, ErrBusy) {
		t.Fatal("wire lookup bypassed cancelled worker bound")
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if !errors.Is(r.Close(ctx), ErrDrain) {
		t.Fatal("wire root worker falsely drained")
	}
	close(release)
	closeRuntime(t, r)
	if _, err := b.ExchangeUDP(context.Background(), bridgeDestination(), query); !errors.Is(err, ErrClosed) {
		t.Fatal("old wire handle survived close")
	}
	if f.queries.Load() != 1 {
		t.Fatal("cancelled wire flooded root workers")
	}
}

func TestNativeSystemDNSBridgeCopiesInputAndOutput(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := &fakeCore{lookupFn: func(string) ([]xnet.IP, error) { close(entered); <-release; return []xnet.IP{{127, 0, 0, 1}}, nil }}
	_, b := bridgeRuntime(t, bridgePrepared(t), f)
	query := bridgeQuery(t, dnsmessage.TypeA)
	ended := make(chan struct{})
	var packet []byte
	var failure error
	go func() {
		defer close(ended)
		packet, failure = b.ExchangeUDP(context.Background(), bridgeDestination(), query)
	}()
	await(t, entered)
	query[0] = 0xff
	query[13] = 'Z'
	close(release)
	await(t, ended)
	if failure != nil {
		t.Fatal(failure)
	}
	answer := bridgeResponse(t, packet, false)
	if answer.ID != 0x1462 || answer.Questions[0].Name.String() != "Caller.Invalid." {
		t.Fatal("mutable input escaped copy")
	}
	packet[0] = 0
	f2 := &fakeCore{}
	_, b2 := bridgeRuntime(t, bridgePrepared(t), f2)
	next, err := b2.ExchangeUDP(context.Background(), bridgeDestination(), bridgeQuery(t, dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if bridgeResponse(t, next, false).ID != 0x1462 {
		t.Fatal("mutable output escaped runtime")
	}
}
