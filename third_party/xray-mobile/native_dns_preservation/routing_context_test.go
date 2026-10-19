package native_dns_preservation_test

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/loopback"
)

// Only Router.Init/PickRoute run here. The fake DNS cannot open a socket, and
// there is no Core instance, dispatcher, handler Start or proxy Process call.
type routingContextDNS struct {
	calls []string
}

func (*routingContextDNS) Type() interface{} { return dns.ClientType() }
func (*routingContextDNS) Start() error      { panic("inert DNS must not start") }
func (*routingContextDNS) Close() error      { return nil }
func (d *routingContextDNS) LookupIP(name string, option dns.IPOption) ([]net.IP, uint32, error) {
	d.calls = append(d.calls, name)
	if name != "route.invalid" || !option.IPv4Enable || !option.IPv6Enable || option.FakeEnable {
		panic("unexpected inert routing DNS request")
	}
	return []net.IP{{192, 0, 2, 23}}, 60, nil
}

func routingContextRouter(t *testing.T, client dns.Client, strategy string, rules ...string) *router.Router {
	t.Helper()
	config := conf.RouterConfig{DomainStrategy: &strategy}
	for _, rule := range rules {
		config.RuleList = append(config.RuleList, json.RawMessage(rule))
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	r := new(router.Router)
	if err := r.Init(context.Background(), built, client, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func routingContextRequest(tag string, skipDNS bool) *routing_session.Context {
	return &routing_session.Context{
		Inbound:  &session.Inbound{Tag: tag},
		Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("route.invalid"), 443)},
		Content:  &session.Content{SkipDNSResolve: skipDNS},
	}
}

func routingContextTag(t *testing.T, r interface {
	PickRoute(routing.Context) (routing.Route, error)
}, ctx routing.Context) string {
	t.Helper()
	route, err := r.PickRoute(ctx)
	if err == common.ErrNoClue {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return route.GetOutboundTag()
}

// The listener's route context must survive the router's second pass. A final
// managed-tag rule is a first-pass match, unlike the dispatcher default handler.
func TestNativeRoutingContextTailCatchall(t *testing.T) {
	const ipRule = `{"type":"field","inboundTag":["managed-input"],"ip":["192.0.2.23/32"],"outboundTag":"caller-ip"}`
	const tail = `{"type":"field","inboundTag":["managed-input"],"outboundTag":"vpn-default"}`
	for _, strategy := range []string{"IPIfNonMatch", "IPOnDemand", "AsIs"} {
		t.Run(strategy, func(t *testing.T) {
			plainDNS, tailDNS := new(routingContextDNS), new(routingContextDNS)
			plain := routingContextRouter(t, plainDNS, strategy, ipRule)
			withTail := routingContextRouter(t, tailDNS, strategy, ipRule, tail)
			plainTag := routingContextTag(t, plain, routingContextRequest("managed-input", false))
			tailTag := routingContextTag(t, withTail, routingContextRequest("managed-input", false))
			wantPlain, wantTail, wantPlainQueries, wantTailQueries := "caller-ip", "caller-ip", 1, 1
			if strategy == "IPIfNonMatch" {
				wantTail, wantTailQueries = "vpn-default", 0
			} else if strategy == "AsIs" {
				wantPlain, wantTail, wantPlainQueries, wantTailQueries = "", "vpn-default", 0, 0
			}
			if plainTag != wantPlain || tailTag != wantTail || len(plainDNS.calls) != wantPlainQueries || len(tailDNS.calls) != wantTailQueries {
				t.Fatalf("real Core routes changed: plain=%q/%d DNS, tail=%q/%d DNS", plainTag, len(plainDNS.calls), tailTag, len(tailDNS.calls))
			}
			t.Logf("actual Router: plain=%s DNS=%d, tail=%s DNS=%d", plainTag, len(plainDNS.calls), tailTag, len(tailDNS.calls))
		})
	}
}

// Bind the control to the pinned implementation, without constructing Core just
// to inject Loopback's unexported dispatcher. Inspect its direct statements:
// Process sets this flag before attaching Content and calling DispatchLink.
func routingContextLoopbackSource(t *testing.T) {
	t.Helper()
	fn := runtime.FuncForPC(reflect.ValueOf((*loopback.Loopback).Process).Pointer())
	if fn == nil {
		t.Fatal("pinned loopback function unavailable")
	}
	filename, _ := fn.FileLine(fn.Entry())
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	source, err := parser.ParseFile(token.NewFileSet(), filename, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	flagAt, attachAt, dispatchAt := -1, -1, -1
	for _, declaration := range source.Decls {
		method, ok := declaration.(*ast.FuncDecl)
		if !ok || method.Name.Name != "Process" || method.Recv == nil {
			continue
		}
		for index, statement := range method.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			if selector, ok := assignment.Lhs[0].(*ast.SelectorExpr); ok {
				name, _ := selector.X.(*ast.Ident)
				literal, _ := assignment.Rhs[0].(*ast.Ident)
				if name != nil && name.Name == "content" && selector.Sel.Name == "SkipDNSResolve" && literal != nil && literal.Name == "true" {
					flagAt = index
				}
			}
			if call, ok := assignment.Rhs[0].(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
					if selector.Sel.Name == "ContextWithContent" {
						attachAt = index
					} else if selector.Sel.Name == "DispatchLink" {
						dispatchAt = index
					}
				}
			}
		}
	}
	if flagAt < 0 || attachAt <= flagAt || dispatchAt <= attachAt {
		t.Fatal("pinned loopback SkipDNSResolve wiring changed; reassess this control")
	}
	for index := 0; index < reflect.TypeOf(conf.LoopbackConfig{}).NumField(); index++ {
		if reflect.TypeOf(conf.LoopbackConfig{}).Field(index).Tag.Get("json") == "skipDNSResolve" {
			t.Fatal("loopback now exposes a flag override; reassess this control")
		}
	}
}

func TestNativeRoutingContextLoopbackDNS(t *testing.T) {
	routingContextLoopbackSource(t)
	const rule = `{"type":"field","inboundTag":["caller-input"],"ip":["192.0.2.23/32"],"outboundTag":"caller-ip"}`
	for _, strategy := range []string{"IPIfNonMatch", "IPOnDemand"} {
		t.Run(strategy, func(t *testing.T) {
			client := new(routingContextDNS)
			r := routingContextRouter(t, client, strategy, rule)
			if got := routingContextTag(t, r, routingContextRequest("caller-input", false)); got != "caller-ip" || len(client.calls) != 1 {
				t.Fatalf("positive DNS routing control failed: %q/%d", got, len(client.calls))
			}
			if got := routingContextTag(t, r, routingContextRequest("caller-input", true)); got != "" || len(client.calls) != 1 {
				t.Fatalf("loopback flag no longer suppresses actual router DNS: %q/%d", got, len(client.calls))
			}
			t.Log("actual Router: original=caller-ip DNS=1; loopback flag=ErrNoClue DNS=0 additional")
		})
	}
}
