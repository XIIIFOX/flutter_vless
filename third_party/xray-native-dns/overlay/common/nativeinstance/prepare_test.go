package nativeinstance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

func testPolicy() Policy {
	return Policy{RequiredCapability: CapabilityID, Resolver: netip.MustParseAddrPort("127.0.0.1:53"), DefaultOutboundIndex: 1, LookupTimeout: 50 * time.Millisecond}
}
func testSource() []byte {
	return []byte(`{
 "log":{"access":"private-canary-access","error":"private-canary-error","loglevel":"debug","dnsLog":true},
 "inbounds":[{"listen":"127.0.0.1","port":12345,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"private-user","pass":"private-password"}]}}],
 "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}},{"protocol":"freedom"}],
 "dns":{"queryStrategy":"UseIPv4","hosts":{"full:static.invalid":"127.0.0.1"}}
 }`)
}
func mustPrepared(t *testing.T) *Prepared {
	t.Helper()
	p, err := PrepareJSON(testSource(), testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func replaceSource(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(testSource(), &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func firstOutbound(object map[string]any) map[string]any {
	return object["outbounds"].([]any)[0].(map[string]any)
}
func firstInbound(object map[string]any) map[string]any {
	return object["inbounds"].([]any)[0].(map[string]any)
}
func dnsFeature(t *testing.T, c *core.Config) *appdns.Config {
	t.Helper()
	for _, value := range c.App {
		if value.Type == "xray.app.dns.Config" {
			result, err := value.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			return result.(*appdns.Config)
		}
	}
	t.Fatal("DNS feature missing")
	return nil
}

func TestNativeInstancePreparedRetainsExactSourceAndCloneIdentity(t *testing.T) {
	source := testSource()
	original := append([]byte(nil), source...)
	policy := testPolicy()
	prepared, err := PrepareJSON(source, policy)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(original)
	if prepared.SourceDigest() != hex.EncodeToString(hash[:]) || !bytes.Equal(source, original) {
		t.Fatal("source identity changed")
	}
	source[0] = 'x'
	policy.DefaultOutboundIndex = 0
	policy.Resolver = netip.MustParseAddrPort("127.0.0.2:53")
	if !bytes.Equal(prepared.source, original) || prepared.policy.DefaultOutboundIndex != 1 || prepared.policy.Resolver != testPolicy().Resolver {
		t.Fatal("caller mutation reached preparation")
	}
	a, bindingsA, err := prepared.clone()
	if err != nil {
		t.Fatal(err)
	}
	b, bindingsB, err := prepared.clone()
	if err != nil {
		t.Fatal(err)
	}
	for index := range a.Outbound {
		if a.Outbound[index] == b.Outbound[index] || a.Outbound[index] == prepared.blueprint.Outbound[index] || bindingsA[index].Key != a.Outbound[index] || bindingsB[index].Key != b.Outbound[index] || bindingsA[index].SourceIndex != index || bindingsA[index].Tag != a.Outbound[index].Tag {
			t.Fatal("bindings do not own exact cloned pointer/index")
		}
	}
	if !proto.Equal(dnsFeature(t, a), dnsFeature(t, prepared.blueprint)) {
		t.Fatal("caller DNS changed")
	}
	a.Outbound[0].Tag = "mutated"
	if prepared.blueprint.Outbound[0].Tag != "" || b.Outbound[0].Tag != "" {
		t.Fatal("clone leaked mutation")
	}
}

func TestNativeInstancePrivateCopyBeforeBuildAndClosedErrors(t *testing.T) {
	prepared := mustPrepared(t)
	if bytes.Contains(prepared.normalized, []byte("private-canary")) || !bytes.Contains(prepared.source, []byte("private-canary")) {
		t.Fatal("private sink/source isolation failed")
	}
	var object map[string]any
	if json.Unmarshal(prepared.normalized, &object) != nil {
		t.Fatal("bad private JSON")
	}
	log := object["log"].(map[string]any)
	if log["loglevel"] != "none" || log["access"] != "none" || log["error"] != "none" || log["dnsLog"] != false {
		t.Fatal("private log sink remained")
	}
	source := []byte(`{"outbounds":[{"protocol":"private-secret-protocol"}]}`)
	_, err := PrepareJSON(source, testPolicy())
	if !errors.Is(err, ErrUnsupported) || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("raw decoder/build detail exported")
	}
}

func TestNativeInstanceJSONCommentsAndTrailingRefusal(t *testing.T) {
	source := append([]byte("// private comment\n"), testSource()...)
	if _, err := PrepareJSON(source, testPolicy()); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{" {}", " null", " broken"} {
		if _, err := PrepareJSON(append(append([]byte(nil), source...), suffix...), testPolicy()); !errors.Is(err, ErrDocument) {
			t.Fatal("trailing document accepted")
		}
	}
	for _, source := range [][]byte{nil, []byte("null"), []byte("[]"), []byte(`{"log":{},"LOG":{}}`), []byte(`{"outbounds":[{"protocol":"freedom","PROTOCOL":"socks"}]}`)} {
		if _, err := PrepareJSON(source, testPolicy()); !errors.Is(err, ErrDocument) {
			t.Fatal("invalid/ambiguous source accepted")
		}
	}
}

func TestNativeInstancePolicyFailClosed(t *testing.T) {
	tests := map[string]func(*Policy){
		"capability":  func(p *Policy) { p.RequiredCapability = "published" },
		"invalid":     func(p *Policy) { p.Resolver = netip.AddrPort{} },
		"ipv6":        func(p *Policy) { p.Resolver = netip.MustParseAddrPort("[::1]:53") },
		"mapped":      func(p *Policy) { p.Resolver = netip.MustParseAddrPort("[::ffff:127.0.0.1]:53") },
		"unspecified": func(p *Policy) { p.Resolver = netip.MustParseAddrPort("0.0.0.0:53") },
		"multicast":   func(p *Policy) { p.Resolver = netip.MustParseAddrPort("224.0.0.1:53") },
		"port":        func(p *Policy) { p.Resolver = netip.MustParseAddrPort("127.0.0.1:0") },
		"index":       func(p *Policy) { p.DefaultOutboundIndex = -1 },
		"long":        func(p *Policy) { p.LookupTimeout = 5 * time.Second },
		"short":       func(p *Policy) { p.LookupTimeout = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := testPolicy()
			mutate(&p)
			if _, err := PrepareJSON(testSource(), p); !errors.Is(err, ErrPolicy) {
				t.Fatal("policy accepted")
			}
		})
	}
	p := testPolicy()
	p.LookupTimeout = 0
	if q, err := checkedPolicy(p); err != nil || q.LookupTimeout != 4*time.Second {
		t.Fatal("default bound missing")
	}
	cap := Capabilities()
	if cap.ID != CapabilityID || cap.Schema != 1 || cap.Published || cap.CoreCommit != CoreCommit {
		t.Fatal("wrong capability")
	}
}

func TestNativeInstanceRejectsIndependentGraphsBeforeBuild(t *testing.T) {
	const key = "FLUTTER_VLESS_NATIVE_PREPARE_CANARY"
	before, present := os.LookupEnv(key)
	cases := map[string]func(map[string]any){
		"env":         func(o map[string]any) { o["env"] = map[string]any{key: "private-environment-canary"} },
		"transport":   func(o map[string]any) { o["transport"] = map[string]any{} },
		"api":         func(o map[string]any) { o["api"] = map[string]any{} },
		"metrics":     func(o map[string]any) { o["metrics"] = map[string]any{} },
		"stats":       func(o map[string]any) { o["stats"] = map[string]any{} },
		"reverse":     func(o map[string]any) { o["reverse"] = map[string]any{} },
		"fakeDNS":     func(o map[string]any) { o["fakeDns"] = []any{} },
		"observatory": func(o map[string]any) { o["observatory"] = map[string]any{} },
		"burst":       func(o map[string]any) { o["burstObservatory"] = map[string]any{} },
		"version":     func(o map[string]any) { o["version"] = map[string]any{} },
		"geodata":     func(o map[string]any) { o["geodata"] = map[string]any{} },
		"inboundRealm": func(o map[string]any) {
			firstInbound(o)["streamSettings"] = map[string]any{"finalmask": map[string]any{"tcp": []any{map[string]any{"type": "realm", "settings": map[string]any{}}}}}
		},
		"inboundReality": func(o map[string]any) {
			firstInbound(o)["streamSettings"] = map[string]any{"security": "reality", "realitySettings": map[string]any{"show": true}}
		},
		"inboundOther":  func(o map[string]any) { firstInbound(o)["protocol"] = "http" },
		"outboundProxy": func(o map[string]any) { firstOutbound(o)["protocol"] = "vless" },
		"routerScript":  func(o map[string]any) { o["routing"] = map[string]any{"script": "private-script"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareJSON(replaceSource(t, mutate), testPolicy()); err == nil {
				t.Fatal("unqualified graph accepted")
			}
		})
	}
	after, afterPresent := os.LookupEnv(key)
	if before != after || present != afterPresent {
		t.Fatal("rejected Build mutated process environment")
	}
}

func TestNativeInstanceTypedInboundOutboundAdmission(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wildcard": func(o map[string]any) { firstInbound(o)["listen"] = "0.0.0.0" },
		"hostname": func(o map[string]any) { firstInbound(o)["listen"] = "localhost" },
		"ipv6":     func(o map[string]any) { firstInbound(o)["listen"] = "::1" },
		"range":    func(o map[string]any) { firstInbound(o)["port"] = "12345-12346" },
		"noauth":   func(o map[string]any) { firstInbound(o)["settings"] = map[string]any{"auth": "noauth"} },
		"udp":      func(o map[string]any) { firstInbound(o)["settings"].(map[string]any)["udp"] = true },
		"emptyAccount": func(o map[string]any) {
			firstInbound(o)["settings"].(map[string]any)["accounts"] = []any{map[string]any{"user": "", "pass": "x"}}
		},
		"sniff":      func(o map[string]any) { firstInbound(o)["sniffing"] = map[string]any{"enabled": true} },
		"callerAsIs": func(o map[string]any) { firstOutbound(o)["settings"] = map[string]any{} },
		"callerIPv6": func(o map[string]any) { firstOutbound(o)["settings"] = map[string]any{"domainStrategy": "UseIPv6"} },
		"redirect":   func(o map[string]any) { firstOutbound(o)["settings"].(map[string]any)["redirect"] = "127.0.0.1:53" },
		"finalRule": func(o map[string]any) {
			firstOutbound(o)["settings"].(map[string]any)["finalRules"] = []any{map[string]any{"action": "allow"}}
		},
		"mux":    func(o map[string]any) { firstOutbound(o)["mux"] = map[string]any{"enabled": true} },
		"target": func(o map[string]any) { firstOutbound(o)["targetStrategy"] = "UseIPv4" },
		"socket": func(o map[string]any) {
			firstOutbound(o)["streamSettings"] = map[string]any{"sockopt": map[string]any{}}
		},
		"duplicateTag": func(o map[string]any) {
			for _, v := range o["outbounds"].([]any) {
				v.(map[string]any)["tag"] = "same"
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareJSON(replaceSource(t, mutate), testPolicy()); err == nil {
				t.Fatal("unqualified handler accepted")
			}
		})
	}
	// Zero inbounds and explicit raw TCP retain their source semantics without Core.
	for _, mutate := range []func(map[string]any){func(o map[string]any) { delete(o, "inbounds") }, func(o map[string]any) { firstOutbound(o)["streamSettings"] = map[string]any{"network": "raw"} }} {
		if _, err := PrepareJSON(replaceSource(t, mutate), testPolicy()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeInstanceDNSAdmissionAndExactCallerPreservation(t *testing.T) {
	cases := map[string]any{
		"ipv6":     map[string]any{"queryStrategy": "UseIPv6"},
		"system":   map[string]any{"queryStrategy": "UseSystem"},
		"udp":      map[string]any{"servers": []any{"1.1.1.1"}},
		"localTCP": map[string]any{"servers": []any{"tcp+local://1.1.1.1"}},
		"namedTCP": map[string]any{"servers": []any{"tcp://resolver.invalid"}},
		"DoH":      map[string]any{"servers": []any{"https://1.1.1.1/dns-query"}},
		"DoQ":      map[string]any{"servers": []any{"quic+local://1.1.1.1"}},
		"fake":     map[string]any{"servers": []any{"fakedns"}},
		"script":   map[string]any{"script": "private-script"},
		"timeout":  map[string]any{"servers": []any{map[string]any{"address": "tcp://1.1.1.1", "timeoutMs": 4001}}},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			source := replaceSource(t, func(o map[string]any) { o["dns"] = value })
			if _, err := PrepareJSON(source, testPolicy()); err == nil {
				t.Fatal("unqualified DNS accepted")
			}
		})
	}
	for name, value := range map[string]any{"missing": nil, "empty": map[string]any{}, "localhost": map[string]any{"servers": []any{"localhost"}}, "tcp": map[string]any{"queryStrategy": "UseIPv4", "hosts": map[string]any{"full:static.invalid": "127.0.0.1"}, "servers": []any{map[string]any{"address": "tcp://127.0.0.1:5353", "domains": []any{"full:alpha.invalid"}, "queryStrategy": "UseIPv4", "tag": "caller-dns", "timeoutMs": 1000}}, "tag": "root-dns"}} {
		t.Run(name, func(t *testing.T) {
			source := replaceSource(t, func(o map[string]any) {
				if value == nil {
					delete(o, "dns")
				} else {
					o["dns"] = value
				}
			})
			p, err := PrepareJSON(source, testPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if value != nil {
				private, err := privateDocument(source)
				if err != nil {
					t.Fatal(err)
				}
				_ = private
				// The original DNS section equals the private one byte-for-byte after a
				// common canonical marshal; log privacy does not rewrite caller DNS.
				var original, normalized map[string]json.RawMessage
				_ = json.Unmarshal(source, &original)
				_ = json.Unmarshal(p.normalized, &normalized)
				var a, b any
				_ = json.Unmarshal(original["dns"], &a)
				_ = json.Unmarshal(normalized["dns"], &b)
				aa, _ := json.Marshal(a)
				bb, _ := json.Marshal(b)
				if !bytes.Equal(aa, bb) {
					t.Fatal("caller DNS rewritten")
				}
			}
		})
	}
}

func TestNativeInstanceCompiledUnknownGraphRefused(t *testing.T) {
	p := mustPrepared(t)
	for _, name := range []string{"xray.app.observatory.Config", "xray.app.reverse.Config", "private.unknown.Config"} {
		c := proto.Clone(p.blueprint).(*core.Config)
		c.App = append(c.App, &serial.TypedMessage{Type: name})
		if !errors.Is(admitCompiled(c, p.policy), ErrUnsupported) {
			t.Fatal("unknown independent feature accepted")
		}
	}
}
