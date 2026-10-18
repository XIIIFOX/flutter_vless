package native_dns_context_runtime_test

// Actual Core runs only on remote CI, using numeric loopback policy resolvers.
import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/nativeconfig"
	"github.com/xtls/xray-core/common/nativednsruntime"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	featureOutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func localDefaultDNS(answer string, stallEntered chan struct{}, stallEnded chan struct{}) func(*loopServer, net.Conn) error {
	return func(server *loopServer, conn net.Conn) error {
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return err
		}
		if length == 0 || length > 4096 {
			return errors.New("invalid bounded DNS size")
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return err
		}
		query := &wireDNS.Msg{}
		if err := query.Unpack(packet); err != nil {
			return err
		}
		if len(query.Question) != 1 {
			return errors.New("unexpected question count")
		}
		question := query.Question[0]
		server.record(fmt.Sprintf("%s %d", question.Name, question.Qtype))
		if question.Name == "stall.invalid." && stallEntered != nil {
			close(stallEntered)
			defer close(stallEnded)
			_, err := conn.Read(make([]byte, 1))
			if err == nil {
				return errors.New("unexpected data after stalled query")
			}
			return nil
		}
		response := &wireDNS.Msg{}
		response.SetReply(query)
		if question.Name != "default.invalid." && question.Name != "special.invalid." {
			response.Rcode = wireDNS.RcodeRefused
		} else {
			header := wireDNS.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: wireDNS.ClassINET, Ttl: 1}
			switch question.Qtype {
			case wireDNS.TypeA:
				response.Answer = []wireDNS.RR{&wireDNS.A{Hdr: header, A: net.ParseIP(answer)}}
			case wireDNS.TypeAAAA:
				response.Answer = []wireDNS.RR{&wireDNS.AAAA{Hdr: header, AAAA: net.ParseIP("::1")}}
			default:
				response.Rcode = wireDNS.RcodeRefused
			}
		}
		result, err := response.Pack()
		if err != nil {
			return err
		}
		if err = binary.Write(conn, binary.BigEndian, uint16(len(result))); err != nil {
			return err
		}
		_, err = conn.Write(result)
		return err
	}
}

type localDefaultOwner struct {
	engine   *ownedCore
	resolver *nativednsruntime.TCPResolver
	source   *core.Config
}

func startLocalDefault(t *testing.T, rootDNS any, withDNS bool, server *loopServer) *localDefaultOwner {
	t.Helper()
	document := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"protocol": "freedom"},
		},
	}
	if withDNS {
		document["dns"] = rootDNS
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := core.LoadConfig("json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	source := proto.Clone(configuration).(*core.Config)
	plan, err := nativeconfig.AnalyzeRootDNS(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := nativeconfig.ValidateRootDNSCapabilities(plan, map[nativeconfig.RootDNSCapability]bool{
		nativeconfig.DNSLocalSystem: true, nativeconfig.DNSRemoteTCP: true,
	}); err != nil {
		t.Fatal(err)
	}
	bindings := make([]internet.NativeDNSBinding, len(configuration.Outbound))
	for index, handler := range configuration.Outbound {
		bindings[index] = internet.NativeDNSBinding{Key: handler, SourceIndex: index, Tag: handler.Tag, ProxyType: handler.ProxySettings.Type}
	}
	owner, err := internet.NewNativeDNSOwner(bindings)
	if err != nil {
		t.Fatal(err)
	}
	address := server.listener.Addr().(*net.TCPAddr)
	resolver, err := nativednsruntime.NewTCPResolver(owner, 1, xnet.TCPDestination(xnet.ParseAddress(address.IP.String()), xnet.Port(address.Port)), 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx := featureDNS.ContextWithNativeLocalResolver(internet.ContextWithNativeDNSOwner(context.Background(), owner), resolver)
	if _, _, err := resolver.LookupIPContext(ctx, "default.invalid", featureDNS.IPOption{IPv4Enable: true}); !errors.Is(err, nativednsruntime.ErrNotReady) {
		t.Fatal("query before ready", err)
	}
	before := server.activity()
	instance, err := core.NewWithContext(ctx, configuration)
	if err != nil {
		_ = owner.Close()
		_ = resolver.Close()
		t.Fatal("actual scoped Core construction", err)
	}
	engine := &ownedCore{owner: owner, core: instance, config: configuration}
	item := &localDefaultOwner{engine: engine, resolver: resolver, source: source}
	t.Cleanup(func() {
		_ = owner.Close()
		if err := resolver.Close(); err != nil {
			t.Error(err)
		}
		if err := engine.close(); err != nil {
			t.Error(err)
		}
	})
	if server.activity() != before {
		t.Fatal("constructor issued DNS before readiness")
	}
	manager := instance.GetFeature(featureOutbound.ManagerType()).(featureOutbound.Manager)
	if err := owner.SealNativeDNSRuntime(instance, manager); err != nil {
		t.Fatal(err)
	}
	if err := resolver.Bind(instance); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemoveHandler(context.Background(), "caller-tag"); err == nil {
		t.Fatal("sealed manager mutation accepted")
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return item
}

func (owner *localDefaultOwner) client() featureDNS.Client {
	return owner.engine.core.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
}

func requireLocalAnswer(t *testing.T, owner *localDefaultOwner, name, expected string, option featureDNS.IPOption) {
	t.Helper()
	ips, _, err := owner.client().LookupIP(name, option)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP(expected)) {
		t.Fatalf("scoped local %s = %v, %v", name, ips, err)
	}
}

func TestAcceptanceNativeDNSLocalDefault(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || (runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true")) {
		t.Fatal("Actual Core is CI-only")
	}
	var systemAttempts atomic.Int64
	previousStandard, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden system DNS")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previousStandard, previousCore
		if systemAttempts.Load() != 0 {
			t.Error("scoped DNS attempted the system resolver")
		}
	})
	t.Log("PHASE scoped missing/empty/explicit localhost: independent numeric policy resolvers")
	httpA := newLoopServer(t, "tcp4", "127.0.0.1:0", markerProtocol("unused", "LOCAL_A"))
	port := httpA.listener.Addr().(*net.TCPAddr).Port
	httpB := newLoopServer(t, "tcp4", fmt.Sprintf("127.0.0.2:%d", port), markerProtocol("unused", "LOCAL_B"))
	stallEntered, stallEnded := make(chan struct{}), make(chan struct{})
	dnsA := newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS("127.0.0.1", stallEntered, stallEnded))
	dnsB := newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS("127.0.0.2", nil, nil))
	missingA := startLocalDefault(t, nil, false, dnsA)
	missingB := startLocalDefault(t, nil, false, dnsB)
	if !proto.Equal(missingA.source, missingB.source) {
		t.Fatal("missing-DNS sources must be identical")
	}
	for _, item := range []struct {
		owner        *localDefaultOwner
		answer, body string
	}{{missingA, "127.0.0.1", "LOCAL_A"}, {missingB, "127.0.0.2", "LOCAL_B"}, {missingA, "127.0.0.1", "LOCAL_A"}} {
		requireLocalAnswer(t, item.owner, "default.invalid", item.answer, featureDNS.IPOption{IPv4Enable: true})
		marker(t, item.owner.engine, "default.invalid", port, item.body)
	}
	requireLocalAnswer(t, missingA, "default.invalid", "::1", featureDNS.IPOption{IPv6Enable: true})
	for _, root := range []any{
		map[string]any{"queryStrategy": "UseIPv4"},
		map[string]any{"queryStrategy": "UseIPv4", "servers": []string{"localhost"}},
	} {
		owner := startLocalDefault(t, root, true, dnsA)
		requireLocalAnswer(t, owner, "default.invalid", "127.0.0.1", featureDNS.IPOption{IPv4Enable: true})
		marker(t, owner.engine, "default.invalid", port, "LOCAL_A")
		if !proto.Equal(owner.source, owner.engine.config) {
			t.Fatal("root DNS or source changed during scoped preparation")
		}
	}
	t.Log("PHASE mixed root localhost/per-domain TCP, hosts alias/rcode/family filtering")
	special := newLoopServer(t, "tcp4", "127.0.0.1:0", dnsProtocol("special.invalid", "127.0.0.2", wireDNS.TypeA))
	root := map[string]any{
		"queryStrategy": "UseIPv4", "disableCache": true, "disableFallbackIfMatch": true,
		"hosts": map[string]any{"static.invalid": "127.0.0.1", "alias.invalid": "static.invalid", "empty.invalid": "::1", "rcode.invalid": "#5"},
		"servers": []any{
			map[string]any{"address": "tcp://" + special.listener.Addr().String(), "domains": []string{"full:special.invalid"}, "skipFallback": true, "queryStrategy": "UseIPv4", "tag": "caller-dns", "timeoutMs": 1000},
			"localhost",
		},
	}
	mixed := startLocalDefault(t, root, true, dnsA)
	requireLocalAnswer(t, mixed, "special.invalid", "127.0.0.2", featureDNS.IPOption{IPv4Enable: true})
	marker(t, mixed.engine, "special.invalid", port, "LOCAL_B")
	requireLocalAnswer(t, mixed, "default.invalid", "127.0.0.1", featureDNS.IPOption{IPv4Enable: true})
	marker(t, mixed.engine, "default.invalid", port, "LOCAL_A")
	beforeA, beforeB := dnsA.activity(), dnsB.activity()
	requireLocalAnswer(t, mixed, "alias.invalid", "127.0.0.1", featureDNS.IPOption{IPv4Enable: true})
	for _, name := range []string{"empty.invalid", "rcode.invalid"} {
		ips, _, err := mixed.client().LookupIP(name, featureDNS.IPOption{IPv4Enable: true})
		if err == nil || len(ips) != 0 {
			t.Fatal("static refusal returned success", name, ips, err)
		}
	}
	if dnsA.activity() != beforeA || dnsB.activity() != beforeB {
		t.Fatal("static empty/rcode/alias escaped to native DNS")
	}
	t.Log("PHASE closed owner cancels a stalled actual TCP DNS exchange; second owner survives")
	queryEnded := make(chan error, 1)
	go func() {
		_, _, err := missingA.client().LookupIP("stall.invalid", featureDNS.IPOption{IPv4Enable: true})
		queryEnded <- err
	}()
	select {
	case <-stallEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled TCP query never reached owned policy server")
	}
	_ = missingA.engine.owner.Close()
	select {
	case err := <-queryEnded:
		if err == nil {
			t.Fatal("closed-owner late DNS success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closed-owner DNS did not cancel")
	}
	select {
	case <-stallEnded:
	case <-time.After(2 * time.Second):
		t.Fatal("owned DNS TCP socket remained open")
	}
	// Owner cancellation itself must close the real exchange. Closing the
	// delegate before these assertions could mask a broken owner lifetime.
	if err := missingA.resolver.Close(); err != nil {
		t.Fatal(err)
	}
	requireLocalAnswer(t, missingB, "default.invalid", "127.0.0.2", featureDNS.IPOption{IPv4Enable: true})
	marker(t, missingB.engine, "default.invalid", port, "LOCAL_B")
	for _, owner := range []*localDefaultOwner{missingA, missingB, mixed} {
		if !proto.Equal(owner.source, owner.engine.config) {
			t.Fatal("caller compiled source mutated")
		}
	}
	for _, server := range []*loopServer{httpA, httpB, dnsA, dnsB, special} {
		observed, errs := server.observations()
		if len(errs) > 0 || len(observed) == 0 {
			t.Fatalf("missing/unexpected fixture activity: %v %v", observed, errs)
		}
	}
	if systemAttempts.Load() != 0 {
		t.Fatal("system DNS used")
	}
	t.Log("PASS actual scoped local/default DNS: unchanged roots, A/AAAA, policy identity, HTTP bytes, teardown")
}
