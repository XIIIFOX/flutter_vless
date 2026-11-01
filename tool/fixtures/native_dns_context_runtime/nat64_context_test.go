package native_dns_context_runtime_test

// A controlled DNS64-answer/owner-generation test, not a live NAT64 translator
// or Wi-Fi/mobile handover qualification. The actual Core receives AAAA over
// its scoped TCP resolver. Synthesized-prefix data must retain IPv6 identity,
// and a newly bound owner must not reuse another network generation's answer.
import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

func TestAcceptanceNativeDNSNAT64(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("actual DNS64-answer Core runtime is CI-only")
	}
	var systemCalls atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemCalls.Add(1)
		return nil, errors.New("DNS64 fixture forbids OS DNS")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if systemCalls.Load() != 0 {
			t.Error("DNS64 answer escaped to the OS resolver")
		}
	})
	answers := []string{"64:ff9b::c000:201", "64:ff9b:1::c000:201"}
	servers := make([]*loopServer, 2)
	owners := make([]*localDefaultOwner, 2)
	root := map[string]any{"queryStrategy": "UseIPv6", "disableCache": true, "servers": []string{"localhost"}}
	query := func(owner *localDefaultOwner, answer string) {
		t.Helper()
		ips, ttl, err := owner.client().LookupIP("default.invalid", featureDNS.IPOption{IPv6Enable: true})
		if err != nil || len(ips) != 1 || ips[0].To4() != nil || len(ips[0]) != net.IPv6len || !ips[0].Equal(net.ParseIP(answer)) {
			t.Fatalf("DNS64 AAAA changed family/prefix/network owner: %v, %v", ips, err)
		}
		if ttl > 1 {
			t.Fatal("DNS64 response TTL was increased beyond its wire TTL")
		}
		if !proto.Equal(owner.source, owner.engine.config) {
			t.Fatal("DNS64 query rewrote caller DNS configuration")
		}
	}
	for index, answer := range answers {
		servers[index] = newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS(answer, nil, nil))
		owners[index] = startLocalDefault(t, root, true, servers[index])
		query(owners[index], answer)
	}
	if !proto.Equal(owners[0].source, owners[1].source) {
		t.Fatal("network generation fixture changed the caller root configuration")
	}
	query(owners[0], answers[0])
	if err := owners[0].engine.close(); err != nil {
		t.Fatal(err)
	}
	query(owners[1], answers[1])
	if err := owners[1].engine.close(); err != nil {
		t.Fatal(err)
	}
	// Rebind after both old cores closed: the data source, not a stale global
	// cache or the previous owner's DNS64 prefix, defines the new answer.
	fresh := startLocalDefault(t, root, true, servers[0])
	query(fresh, answers[0])
	before := servers[0].activity()
	ips, _, err := fresh.client().LookupIP("default.invalid", featureDNS.IPOption{IPv4Enable: true})
	if err == nil || len(ips) != 0 || servers[0].activity() != before {
		t.Fatal("explicit UseIPv6 silently synthesized an IPv4 fallback or issued a query")
	}
	for index, server := range servers {
		observations, failures := server.observations()
		if len(observations) < 2 || len(failures) != 0 {
			t.Fatalf("DNS64 generation %d did not execute cleanly: %v %v", index, observations, failures)
		}
		for _, observation := range observations {
			if observation != "default.invalid. 28" {
				t.Fatal("DNS64 fixture received a non-AAAA or unrelated DNS query", observation)
			}
		}
	}
	t.Log("DNS64 answer control: both prefixes retained as IPv6; independent owner generations; explicit family; no system DNS; translation/handover not inferred")
}
