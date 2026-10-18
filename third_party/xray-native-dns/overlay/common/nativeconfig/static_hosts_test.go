package nativeconfig

import (
	"reflect"
	"sort"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

func nativeHost(t *testing.T, pattern string, values ...string) *appdns.Config_HostMapping {
	t.Helper()
	rule, err := geodata.ParseDomainRule(pattern, geodata.Domain_Full)
	if err != nil {
		t.Fatal(err)
	}
	mapping := &appdns.Config_HostMapping{Domain: rule}
	for _, value := range values {
		address := net.ParseAddress(value)
		if address.Family().IsDomain() {
			mapping.ProxiedDomain = value
		} else {
			mapping.Ip = append(mapping.Ip, address.IP())
		}
	}
	return mapping
}

func nativeAddressStrings(result StaticHostResult) []string {
	var values []string
	for _, address := range result.Addresses {
		values = append(values, address.IP().String())
	}
	sort.Strings(values)
	return values
}

func TestNativeConfigStaticHostsUseActualCoreMatcherAndNeverCollapseNoMatch(t *testing.T) {
	config := &appdns.Config{StaticHosts: []*appdns.Config_HostMapping{
		nativeHost(t, "full:both.example", "192.0.2.10", "2001:db8::10"),
		nativeHost(t, "domain:suffix.example", "192.0.2.11"),
		nativeHost(t, `regexp:^regex[0-9]+\.example$`, "192.0.2.12"),
		nativeHost(t, "full:empty.example"),
		nativeHost(t, "full:alias.example", "unresolved.example"),
		nativeHost(t, "full:resolved-alias.example", "both.example"),
		nativeHost(t, "full:refused.example", "#5"),
		nativeHost(t, "full:nodata.example", "#0"),
		nativeHost(t, "full:alias-refused.example", "refused.example"),
	}}
	before := proto.Clone(config)
	plan, err := NewStaticHostsPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	both := featuredns.IPOption{IPv4Enable: true, IPv6Enable: true}
	for _, test := range []struct {
		name               string
		option             featuredns.IPOption
		kind               StaticHostKind
		addresses, aliases []string
		rcode              uint16
	}{
		{"absent.example", both, StaticNoMatch, nil, nil, 0},
		{"BOTH.EXAMPLE.", both, StaticAddresses, []string{"192.0.2.10", "2001:db8::10"}, nil, 0},
		{"child.suffix.example", both, StaticAddresses, []string{"192.0.2.11"}, nil, 0},
		{"regex17.example", both, StaticAddresses, []string{"192.0.2.12"}, nil, 0},
		{"empty.example", both, StaticEmpty, nil, nil, 0},
		{"both.example", featuredns.IPOption{IPv6Enable: true}, StaticAddresses, []string{"2001:db8::10"}, nil, 0},
		{"child.suffix.example", featuredns.IPOption{IPv6Enable: true}, StaticEmpty, nil, nil, 0},
		{"alias.example", both, StaticAlias, nil, []string{"unresolved.example"}, 0},
		{"resolved-alias.example", both, StaticAddresses, []string{"192.0.2.10", "2001:db8::10"}, nil, 0},
		{"refused.example", both, StaticRefused, nil, nil, 5},
		{"nodata.example", both, StaticEmpty, nil, nil, 0},
		{"alias-refused.example", both, StaticRefused, nil, nil, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := plan.Lookup(test.name, test.option, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != test.kind || !reflect.DeepEqual(nativeAddressStrings(got), test.addresses) || !reflect.DeepEqual(got.RequiredNames, test.aliases) || got.RCode != test.rcode {
				t.Fatalf("Unexpected matcher plan: kind=%s addresses=%v required=%v rcode=%d", got.Kind, nativeAddressStrings(got), got.RequiredNames, got.RCode)
			}
		})
	}
	if !proto.Equal(config, before) {
		t.Fatal("Caller DNS hosts or query strategy changed")
	}
}

func TestNativeConfigStaticAliasDepthFiveMatchesCoreWithoutPhysicalFallback(t *testing.T) {
	config := &appdns.Config{StaticHosts: []*appdns.Config_HostMapping{
		nativeHost(t, "full:a0.example", "a1.example"), nativeHost(t, "full:a1.example", "a2.example"),
		nativeHost(t, "full:a2.example", "a3.example"), nativeHost(t, "full:a3.example", "a4.example"),
		nativeHost(t, "full:a4.example", "a5.example"), nativeHost(t, "full:a5.example", "a6.example"),
		nativeHost(t, "full:a6.example", "192.0.2.6"), nativeHost(t, "full:cycle.example", "cycle.example"),
	}}
	plan, err := NewStaticHostsPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	for name, required := range map[string]string{"a0.example": "a6.example", "cycle.example": "cycle.example"} {
		got, err := plan.Lookup(name, featuredns.IPOption{IPv4Enable: true}, nil)
		if err != nil || got.Kind != StaticAlias || !reflect.DeepEqual(got.RequiredNames, []string{required}) || got.Addresses != nil {
			t.Fatal("Core depth-limited alias was treated as physical no-match")
		}
	}
}

func TestNativeConfigStaticQueryStrategyAndSnapshots(t *testing.T) {
	both := featuredns.IPOption{IPv4Enable: true, IPv6Enable: true}
	for _, test := range []struct {
		strategy  appdns.QueryStrategy
		system    *featuredns.IPOption
		kind      StaticHostKind
		addresses []string
	}{
		{appdns.QueryStrategy_USE_IP4, nil, StaticAddresses, []string{"192.0.2.1"}},
		{appdns.QueryStrategy_USE_IP6, nil, StaticAddresses, []string{"2001:db8::1"}},
		{appdns.QueryStrategy_USE_SYS, nil, StaticSystemFamilies, nil},
		{appdns.QueryStrategy_USE_SYS, &featuredns.IPOption{IPv6Enable: true}, StaticAddresses, []string{"2001:db8::1"}},
		{appdns.QueryStrategy_USE_SYS, &featuredns.IPOption{}, StaticEmpty, nil},
	} {
		config := &appdns.Config{QueryStrategy: test.strategy, StaticHosts: []*appdns.Config_HostMapping{nativeHost(t, "full:snapshot.example", "192.0.2.1", "2001:db8::1")}}
		before := proto.Clone(config)
		plan, err := NewStaticHostsPlan(config)
		if err != nil {
			t.Fatal(err)
		}
		if plan.QueryStrategy() != test.strategy || !proto.Equal(config, before) {
			t.Fatal("Query strategy changed")
		}
		config.QueryStrategy = appdns.QueryStrategy_USE_IP
		config.StaticHosts[0].Ip[0][0] = 100
		got, err := plan.Lookup("snapshot.example", both, test.system)
		if err != nil || got.Kind != test.kind || !reflect.DeepEqual(nativeAddressStrings(got), test.addresses) {
			t.Fatal("Snapshot/strategy not preserved")
		}
		if len(got.Addresses) != 0 {
			got.Addresses[0].IP()[0] = 99
			again, _ := plan.Lookup("snapshot.example", both, test.system)
			if !reflect.DeepEqual(nativeAddressStrings(again), test.addresses) {
				t.Fatal("Result IP bytes mutate the matcher snapshot")
			}
		}
	}
}

func TestNativeConfigStaticInvalidPatternsHaveSafeErrors(t *testing.T) {
	config := &appdns.Config{StaticHosts: []*appdns.Config_HostMapping{nativeHost(t, "full:private.example", "#private-error")}}
	if _, err := NewStaticHostsPlan(config); err != ErrStaticHosts {
		t.Fatal("Invalid RCode was not safely rejected")
	}
	if _, err := NewStaticHostsPlan(&appdns.Config{StaticHosts: []*appdns.Config_HostMapping{nil}}); err != ErrStaticHosts {
		t.Fatal("Malformed compiled mapping was not safely rejected")
	}
	if _, err := NewStaticHostsPlan(&appdns.Config{QueryStrategy: 999}); err != ErrStaticHosts {
		t.Fatal("Unknown qstrategy accepted")
	}
}
