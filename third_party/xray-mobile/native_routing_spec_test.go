package XRay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/router"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

func nativeSpecDocument(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	user, password := hex.EncodeToString(random[:8]), hex.EncodeToString(random[8:])
	config := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"dns": map[string]any{"queryStrategy": "UseIPv4", "servers": []any{"tcp://1.1.1.1"}, "hosts": map[string]any{"caller.invalid": "192.0.2.8"}},
		"api": map[string]any{"tag": "caller-api", "listen": "127.0.0.1:19894", "services": []any{"StatsService"}},
		"inbounds": []any{
			map[string]any{"tag": "managed", "listen": "127.0.0.1", "port": 19891, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": user, "pass": password}}, "udp": true}},
			map[string]any{"tag": "caller", "listen": "127.0.0.1", "port": 19892, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
			map[string]any{"listen": "127.0.0.1", "port": 19893, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
		},
		"outbounds": []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}, map[string]any{"tag": "selected", "protocol": "freedom"}, map[string]any{"tag": "dns", "protocol": "dns"}},
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []any{"managed"}, "ip": []any{"198.18.0.2/32"}, "port": "53", "network": "tcp,udp", "outboundTag": "dns"},
			map[string]any{"type": "field", "inboundTag": []any{"caller"}, "domain": []any{"full:caller.invalid"}, "outboundTag": "selected"},
			map[string]any{"type": "field", "inboundTag": []any{"private-bootstrap"}, "outboundTag": "blocked"},
		}},
	}
	spec := map[string]any{"version": 1, "managed_inbound_index": 0, "managed_inbound_tag": "managed", "auth_user": user,
		"source_inbound_index": 1, "default_outbound_tag": "selected", "guard_rule_indices": []any{0, 2}}
	return config, spec
}

func nativeSpecBytes(t *testing.T, config, spec map[string]any) ([]byte, []byte) {
	t.Helper()
	source, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source)
	spec["source_sha256"] = hex.EncodeToString(digest[:])
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return source, encoded
}

func nativeSpecRouter(t *testing.T, prepared *nativeRoutingPrepared) *router.Config {
	t.Helper()
	for _, app := range prepared.config.App {
		if app.Type == "xray.app.router.Config" {
			value, err := app.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			return value.(*router.Config)
		}
	}
	t.Fatal("missing compiled caller router")
	return nil
}

func TestNativeRoutingSpecPreparedIdentity(t *testing.T) {
	config, spec := nativeSpecDocument(t)
	source, encoded := nativeSpecBytes(t, config, spec)
	originalSource, originalSpec := bytes.Clone(source), bytes.Clone(encoded)
	prepared, code := prepareNativeRouting(source, encoded)
	if code != 0 || prepared == nil || prepared.key != prepared.config.Inbound[0] || prepared.managedIndex != 0 || prepared.managedTag != "managed" || prepared.authUser != spec["auth_user"] {
		t.Fatal("final compiled private identity was not retained")
	}
	if !prepared.aliasEnabled || prepared.alias != "caller" || prepared.defaultTag != "selected" || prepared.diagnostics {
		t.Fatal("native routing choices changed")
	}
	// Compare the whole compiled object to ordinary privacy/decode/build. Private
	// guard extraction must not rewrite the caller DNS/API/routing or source order.
	private, _, _, err := privateConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	want, err := decoded.Build()
	if err != nil || !proto.Equal(prepared.config, want) {
		t.Fatal("compiled caller configuration was transformed")
	}
	caller := nativeSpecRouter(t, prepared)
	if len(prepared.guards) != 2 || !proto.Equal(prepared.guards[0], caller.Rule[0]) || !proto.Equal(prepared.guards[1], caller.Rule[2]) || prepared.guards[0] == caller.Rule[0] {
		t.Fatal("guards were not exact independent clones")
	}
	prepared.guards[0].InboundTag[0] = "mutated-copy"
	if caller.Rule[0].InboundTag[0] != "managed" || !bytes.Equal(source, originalSource) || !bytes.Equal(encoded, originalSpec) {
		t.Fatal("guard or parser mutated retained caller state")
	}
}

func TestNativeRoutingSpecStrictSyntax(t *testing.T) {
	config, spec := nativeSpecDocument(t)
	source, valid := nativeSpecBytes(t, config, spec)
	for _, name := range []string{"version", "source_sha256", "managed_inbound_index", "managed_inbound_tag", "auth_user"} {
		copy := make(map[string]any, len(spec))
		for k, v := range spec {
			copy[k] = v
		}
		delete(copy, name)
		b, _ := json.Marshal(copy)
		if _, code := prepareNativeRouting(source, b); code != 16 {
			t.Fatalf("missing %s accepted: %d", name, code)
		}
	}
	for _, bad := range []string{
		`null`, `[]`, `{}`, string(valid) + `{}`, strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(valid), `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		strings.Replace(string(valid), `"version":1`, `"version":1,"unknown":0`, 1),
		strings.Replace(string(valid), `"version":1`, `"Version":1`, 1),
		strings.Replace(string(valid), `"version":1`, `"version":null`, 1),
		strings.Replace(string(valid), `"version":1`, `"version":2`, 1),
		strings.Replace(string(valid), `"managed_inbound_index":0`, `"managed_inbound_index":0.0`, 1),
		strings.Replace(string(valid), `"default_outbound_tag":"selected"`, `"default_outbound_tag":null`, 1),
		strings.Replace(string(valid), `"guard_rule_indices":[0,2]`, `"guard_rule_indices":[null]`, 1),
	} {
		if _, code := prepareNativeRouting(source, []byte(bad)); code != 16 {
			t.Fatalf("invalid spec syntax accepted: %d", code)
		}
	}
	for _, name := range []string{"version", "managed_inbound_index", "source_inbound_index", "auth_user", "managed_inbound_tag", "guard_rule_indices", "default_outbound_tag"} {
		for _, value := range []any{true, map[string]any{}, []any{}} {
			copy := make(map[string]any, len(spec))
			for k, v := range spec {
				copy[k] = v
			}
			copy[name] = value
			// An empty array is a valid guard list, unlike the other field types.
			if name == "guard_rule_indices" {
				if _, ok := value.([]any); ok {
					continue
				}
			}
			b, _ := json.Marshal(copy)
			if _, code := prepareNativeRouting(source, b); code != 16 {
				t.Fatalf("wrong type %s accepted: %d", name, code)
			}
		}
	}
	upper := strings.Replace(string(valid), spec["source_sha256"].(string), strings.ToUpper(spec["source_sha256"].(string)), 1)
	if _, code := prepareNativeRouting(source, []byte(upper)); code != 0 {
		t.Fatal("valid uppercase hex digest refused")
	}
	if _, code := prepareNativeRouting(append(bytes.Clone(source), ' '), valid); code != 17 {
		t.Fatal("digest was not bound to exact raw source bytes")
	}
}

func TestNativeRoutingSpecSelectionRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(map[string]any, map[string]any)
		code   int64
	}{
		"bad-managed-index":   {func(_ map[string]any, s map[string]any) { s["managed_inbound_index"] = -1 }, 18},
		"foreign-managed-tag": {func(_ map[string]any, s map[string]any) { s["managed_inbound_tag"] = "caller" }, 18},
		"foreign-auth-user":   {func(_ map[string]any, s map[string]any) { s["auth_user"] = "foreign" }, 18},
		"no-auth": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["auth"] = "noauth"
		}, 18},
		"public-listen": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0"
		}, 18},
		"extra-port": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["port"] = "19891-19892"
		}, 18},
		"private-tls": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{"security": "tls"}
		}, 18},
		"private-ws": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{"network": "ws"}
		}, 18},
		"private-transparent": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{"sockopt": map[string]any{"tproxy": "tproxy"}}
		}, 18},
		"private-service-discovery": {func(c map[string]any, _ map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{"sockopt": map[string]any{"addressPortStrategy": "srvportonly"}}
		}, 18},
		"source-is-managed": {func(_ map[string]any, s map[string]any) { s["source_inbound_index"] = 0 }, 19},
		"missing-source":    {func(_ map[string]any, s map[string]any) { s["source_inbound_index"] = 20 }, 19},
		"missing-default":   {func(_ map[string]any, s map[string]any) { s["default_outbound_tag"] = "absent" }, 20},
		"duplicate-default": {func(c map[string]any, _ map[string]any) {
			c["outbounds"] = append(c["outbounds"].([]any), map[string]any{"tag": "selected", "protocol": "blackhole"})
		}, 20},
		"duplicate-guard": {func(_ map[string]any, s map[string]any) { s["guard_rule_indices"] = []any{0, 0} }, 21},
		"missing-guard":   {func(_ map[string]any, s map[string]any) { s["guard_rule_indices"] = []any{50} }, 21},
		"unscoped-guard": {func(c map[string]any, _ map[string]any) {
			delete(c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any), "inboundTag")
		}, 21},
		"empty-inbound-scope": {func(c map[string]any, _ map[string]any) {
			c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)["inboundTag"] = []any{""}
		}, 21},
		"bad-condition-regexp": {func(c map[string]any, _ map[string]any) {
			c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)["attrs"] = map[string]any{"test": "["}
		}, 21},
		"webhook-guard": {func(c map[string]any, _ map[string]any) {
			c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)["webhook"] = map[string]any{"url": "https://synthetic.invalid/hook"}
		}, 21},
		"balancing-guard": {func(c map[string]any, _ map[string]any) {
			rule := c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			delete(rule, "outboundTag")
			rule["balancerTag"] = "caller-balancer"
		}, 21},
	} {
		t.Run(name, func(t *testing.T) {
			config, spec := nativeSpecDocument(t)
			tc.mutate(config, spec)
			source, encoded := nativeSpecBytes(t, config, spec)
			if prepared, code := prepareNativeRouting(source, encoded); code != tc.code || prepared != nil {
				t.Fatalf("wrong closed refusal: got %d want %d", code, tc.code)
			}
		})
	}
}

func TestNativeRoutingSpecOptionsAndEnv(t *testing.T) {
	config, spec := nativeSpecDocument(t)
	spec["source_inbound_index"], spec["guard_rule_indices"], spec["default_outbound_tag"] = nil, nil, ""
	source, encoded := nativeSpecBytes(t, config, spec)
	prepared, code := prepareNativeRouting(source, encoded)
	if code != 0 || prepared.aliasEnabled || prepared.defaultTag != "" || len(prepared.guards) != 0 {
		t.Fatal("disabled optional native choices changed Core defaults")
	}
	spec["source_inbound_index"] = 2
	source, encoded = nativeSpecBytes(t, config, spec)
	prepared, code = prepareNativeRouting(source, encoded)
	if code != 0 || !prepared.aliasEnabled || prepared.alias != "" {
		t.Fatal("explicit untagged source alias collapsed into disabled")
	}
	config["log"] = map[string]any{"loglevel": "error"}
	source, encoded = nativeSpecBytes(t, config, spec)
	prepared, code = prepareNativeRouting(source, encoded)
	if code != 0 || prepared.level != xlog.Severity_Error || !prepared.diagnostics {
		t.Fatal("privacy diagnostics severity changed")
	}
	t.Setenv("FLUTTER_VLESS_ROUTING_SPEC_ENV_TEST", "original")
	config["env"] = map[string]any{"FLUTTER_VLESS_ROUTING_SPEC_ENV_TEST": "candidate"}
	config["outbounds"].([]any)[0].(map[string]any)["protocol"] = "synthetic-unknown-protocol"
	source, encoded = nativeSpecBytes(t, config, spec)
	if prepared, code := prepareNativeRouting(source, encoded); code != 5 || prepared != nil || os.Getenv("FLUTTER_VLESS_ROUTING_SPEC_ENV_TEST") != "original" {
		t.Fatal("env denial did not precede Build or changed process environment")
	}
	delete(config, "env")
	source, encoded = nativeSpecBytes(t, config, spec)
	if _, code := prepareNativeRouting(source, encoded); code != 3 {
		t.Fatal("build failure stage was not retained")
	}
	for _, tc := range []struct {
		source []byte
		code   int64
	}{
		{[]byte(`null`), 1},
		{[]byte(`{"inbounds":[{"port":{}}]}`), 2},
	} {
		digest := sha256.Sum256(tc.source)
		spec["source_sha256"] = hex.EncodeToString(digest[:])
		encoded, _ := json.Marshal(spec)
		if _, code := prepareNativeRouting(tc.source, encoded); code != tc.code {
			t.Fatalf("wrong preparation stage: got %d want %d", code, tc.code)
		}
	}
}
