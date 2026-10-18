package freedom

import (
	"context"
	"errors"
	stdnet "net"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type nativeFinalRuleDialer struct{ calls int }

func (d *nativeFinalRuleDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.calls++
	return nil, errors.New("synthetic dialer must not be called")
}
func (*nativeFinalRuleDialer) DestIpAddress() net.IP                                 { return nil }
func (*nativeFinalRuleDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// Direct Process calls with fake links/dialer and a refusing process-local
// resolver. No Core is constructed; even a regression cannot open a DNS socket.
func TestNativeDNSFreedomAsIsFinalAndDefaultRulesRefuseBeforeResolver(t *testing.T) {
	var queries atomic.Int64
	previousStandard, previousCore := stdnet.DefaultResolver, net.DefaultResolver
	trap := &stdnet.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (stdnet.Conn, error) {
		queries.Add(1)
		return nil, errors.New("synthetic resolver refuses all sockets")
	}}
	stdnet.DefaultResolver, net.DefaultResolver = trap, trap
	defer func() { stdnet.DefaultResolver, net.DefaultResolver = previousStandard, previousCore }()
	for _, defaultInbound := range []bool{false, true} {
		handler := &Handler{config: &Config{}, resolveStrategy: internet.DomainStrategy_AS_IS}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("must-not-resolve.invalid"), 443)}})
		if defaultInbound {
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "vless"})
		} else {
			handler.finalRules = []*FinalRule{{action: RuleAction_Allow}}
		}
		dialer := &nativeFinalRuleDialer{}
		if err := handler.Process(ctx, &transport.Link{}, dialer); !errors.Is(err, internet.ErrNativeDNSUnsupported) {
			t.Fatalf("AsIs final-rule lookup was not rejected: %v", err)
		}
		if dialer.calls != 0 || queries.Load() != 0 {
			t.Fatal("AsIs precheck reached a system resolver or dialer")
		}
	}
}
