package nativeconfig

import (
	"errors"
	"strings"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

var ErrStaticHosts = errors.New("native preparation static hosts invalid")

type StaticHostKind string

const (
	StaticNoMatch        StaticHostKind = "no-match"
	StaticAddresses      StaticHostKind = "addresses"
	StaticEmpty          StaticHostKind = "empty-answer"
	StaticRefused        StaticHostKind = "rcode"
	StaticAlias          StaticHostKind = "alias-required"
	StaticSystemFamilies StaticHostKind = "system-families-required"
)

type StaticHostResult struct {
	Kind          StaticHostKind
	Addresses     []net.Address
	RequiredNames []string // unresolved aliases, never permission to call a physical resolver
	RCode         uint16
	Option        featuredns.IPOption
}

// StaticHostsPlan snapshots only the compiled static matcher and query strategy.
// The original root DNS, host patterns, server list and qstrategy stay unchanged.
type StaticHostsPlan struct {
	hosts    *appdns.StaticHosts
	strategy appdns.QueryStrategy
}

func NewStaticHostsPlan(config *appdns.Config) (plan *StaticHostsPlan, resultErr error) {
	defer func() {
		if recover() != nil {
			plan, resultErr = nil, ErrStaticHosts
		}
	}()
	if config == nil {
		config = &appdns.Config{}
	}
	copy := proto.Clone(config).(*appdns.Config)
	if copy.QueryStrategy < appdns.QueryStrategy_USE_IP || copy.QueryStrategy > appdns.QueryStrategy_USE_SYS {
		return nil, ErrStaticHosts
	}
	hosts, err := appdns.NewStaticHosts(copy.StaticHosts)
	if err != nil {
		return nil, ErrStaticHosts
	}
	return &StaticHostsPlan{hosts, copy.QueryStrategy}, nil
}

func (plan *StaticHostsPlan) QueryStrategy() appdns.QueryStrategy { return plan.strategy }

// Lookup uses Core's unmodified matcher, including regex/domain precedence and
// depth-5 alias traversal. A system-family snapshot is mandatory for UseSystem;
// this helper never calls CheckRoutes, DNS, or an OS resolver to obtain it.
func (plan *StaticHostsPlan) Lookup(name string, option featuredns.IPOption, systemFamilies *featuredns.IPOption) (StaticHostResult, error) {
	result := StaticHostResult{Option: option}
	if plan == nil || plan.hosts == nil {
		return result, ErrStaticHosts
	}
	name = strings.TrimSuffix(name, ".") // same FQDN normalization as DNS.LookupIP
	if name == "" {
		return result, ErrStaticHosts
	}
	switch plan.strategy {
	case appdns.QueryStrategy_USE_IP4:
		result.Option.IPv6Enable = false
	case appdns.QueryStrategy_USE_IP6:
		result.Option.IPv4Enable = false
	case appdns.QueryStrategy_USE_SYS:
		if systemFamilies == nil {
			result.Kind = StaticSystemFamilies
			return result, nil
		}
		result.Option.IPv4Enable = option.IPv4Enable && systemFamilies.IPv4Enable
		result.Option.IPv6Enable = option.IPv6Enable && systemFamilies.IPv6Enable
	}
	if !result.Option.IPv4Enable && !result.Option.IPv6Enable {
		result.Kind = StaticEmpty
		return result, nil
	}
	addresses, err := plan.hosts.Lookup(name, result.Option)
	if err != nil {
		if errors.Is(err, featuredns.ErrEmptyResponse) {
			result.Kind = StaticEmpty
			return result, nil
		}
		var rcode featuredns.RCodeError
		if errors.As(err, &rcode) {
			result.Kind, result.RCode = StaticRefused, uint16(rcode)
			return result, nil
		}
		return result, ErrStaticHosts
	}
	switch {
	case addresses == nil:
		result.Kind = StaticNoMatch
	case len(addresses) == 0:
		result.Kind = StaticEmpty
	case len(addresses) == 1 && addresses[0].Family().IsDomain():
		result.Kind = StaticAlias
		result.RequiredNames = []string{addresses[0].Domain()}
	default:
		result.Kind = StaticAddresses
		for _, address := range addresses {
			if !address.Family().IsIP() {
				return StaticHostResult{}, ErrStaticHosts
			}
			// Core matcher responses retain backing IP bytes; callers cannot mutate its snapshot.
			result.Addresses = append(result.Addresses, net.IPAddress(append(net.IP(nil), address.IP()...)))
		}
	}
	return result, nil
}
