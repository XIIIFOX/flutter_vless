package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func foldedRoot(object map[string]any, name string) (any, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func foldedKeys(object map[string]any, name string) []string {
	var keys []string
	for key := range object {
		if strings.EqualFold(key, name) {
			keys = append(keys, key)
		}
	}
	return keys
}

// The private statistics API may supply exactly the two missing inbound flags.
// Every existing key/value (including aliases, false, null and opaque fields)
// remains byte-for-byte JSON-equivalent; caller APIs and null stats opt out.
func expectedCallerPolicy(source map[string]any, original any) any {
	if _, present := foldedRoot(source, "api"); present {
		return original
	}
	if stats, present := foldedRoot(source, "stats"); present && stats == nil {
		return original
	}
	policy, ok := original.(map[string]any)
	if !ok {
		return original
	}
	keys := foldedKeys(policy, "system")
	if len(keys) > 1 {
		return original
	}
	key := "system"
	if len(keys) == 1 {
		key = keys[0]
	}
	system := map[string]any{}
	if value, present := policy[key]; present {
		system, ok = value.(map[string]any)
		if !ok {
			return original
		}
	}
	fields := []string{"statsInboundUplink", "statsInboundDownlink"}
	for _, field := range fields {
		if len(foldedKeys(system, field)) > 1 {
			return original
		}
	}
	nextSystem := make(map[string]any, len(system)+2)
	for name, value := range system {
		nextSystem[name] = value
	}
	for _, field := range fields {
		if len(foldedKeys(system, field)) == 0 {
			nextSystem[field] = true
		}
	}
	nextPolicy := make(map[string]any, len(policy)+1)
	for name, value := range policy {
		nextPolicy[name] = value
	}
	nextPolicy[key] = nextSystem
	return nextPolicy
}

func callerServiceRootsError(source, effective map[string]any) error {
	for _, name := range []string{"api", "stats", "policy"} {
		want, present := foldedRoot(source, name)
		if !present {
			continue
		}
		if name == "policy" {
			want = expectedCallerPolicy(source, want)
		}
		got, retained := foldedRoot(effective, name)
		wantJSON, wantErr := json.Marshal(want)
		gotJSON, gotErr := json.Marshal(got)
		if !retained || wantErr != nil || gotErr != nil || !bytes.Equal(wantJSON, gotJSON) {
			return fmt.Errorf("caller %s subtree changed beyond missing private inbound-statistics defaults", name)
		}
	}
	return nil
}

func assertCallerServiceRoots(t *testing.T, source, effective map[string]any) {
	t.Helper()
	if err := callerServiceRootsError(source, effective); err != nil {
		t.Fatal(err)
	}
}

// Standalone stdlib-only contract controls: go test service_roots_test.go.
// The same controls run inside the actual native-preparation corpus in CI.
func TestCallerServiceRootsContract(t *testing.T) {
	const levels = `"levels":{"8":{"bufferSize":3,"handshake":4}}`
	const defaults = `"statsInboundUplink":true,"statsInboundDownlink":true`
	cases := []struct {
		name, source, effective string
		accepted                bool
	}{
		{"levels-only", `{"stats":{},"policy":{` + levels + `}}`, `{"stats":{},"policy":{` + levels + `,"system":{` + defaults + `}}}`, true},
		{"empty-system", `{"policy":{"system":{}}}`, `{"policy":{"system":{` + defaults + `}}}`, true},
		{"partial-false", `{"policy":{"system":{"statsInboundUplink":false,"opaque":7}}}`, `{"policy":{"system":{"statsInboundUplink":false,"statsInboundDownlink":true,"opaque":7}}}`, true},
		{"false-null-aliases", `{"Policy":{"System":{"StatſInboundUplink":false,"StatsInboundDownlink":null}}}`, `{"Policy":{"System":{"StatſInboundUplink":false,"StatsInboundDownlink":null}}}`, true},
		{"caller-api-opt-out", `{"API":null,"policy":{` + levels + `}}`, `{"api":null,"policy":{` + levels + `}}`, true},
		{"null-stats-opt-out", `{"stats":null,"policy":{` + levels + `}}`, `{"stats":null,"policy":{` + levels + `}}`, true},
		{"null-system-opt-out", `{"policy":{"system":null}}`, `{"policy":{"system":null}}`, true},
		{"null-policy-opt-out", `{"policy":null}`, `{"policy":null}`, true},
		{"ambiguous-system-preserved", `{"policy":{"system":{},"System":{}}}`, `{"policy":{"system":{},"System":{}}}`, true},
		{"ambiguous-counter-preserved", `{"policy":{"system":{"statsInboundUplink":false,"StatsInboundUplink":null}}}`, `{"policy":{"system":{"statsInboundUplink":false,"StatsInboundUplink":null}}}`, true},
		{"negative-level-mutation", `{"policy":{` + levels + `}}`, `{"policy":{"levels":{"8":{"bufferSize":4,"handshake":4}},"system":{` + defaults + `}}}`, false},
		{"negative-unrelated-default", `{"policy":{}}`, `{"policy":{"system":{` + defaults + `,"statsOutboundUplink":true}}}`, false},
		{"negative-missing-default", `{"policy":{}}`, `{"policy":{"system":{"statsInboundUplink":true}}}`, false},
		{"negative-false-overwrite", `{"policy":{"system":{"statsInboundUplink":false}}}`, `{"policy":{"system":{` + defaults + `}}}`, false},
		{"negative-null-overwrite", `{"policy":{"system":{"statsInboundUplink":null}}}`, `{"policy":{"system":{` + defaults + `}}}`, false},
		{"negative-alias-rewrite", `{"policy":{"System":{"StatsInboundUplink":false}}}`, `{"policy":{"system":{"statsInboundUplink":false,"statsInboundDownlink":true}}}`, false},
		{"negative-caller-api-defaults", `{"api":null,"policy":{}}`, `{"api":null,"policy":{"system":{` + defaults + `}}}`, false},
		{"negative-null-stats-defaults", `{"stats":null,"policy":{}}`, `{"stats":null,"policy":{"system":{` + defaults + `}}}`, false},
		{"negative-null-system-defaults", `{"policy":{"system":null}}`, `{"policy":{"system":{` + defaults + `}}}`, false},
		{"negative-ambiguous-counter-defaults", `{"policy":{"system":{"statsInboundUplink":false,"StatsInboundUplink":null}}}`, `{"policy":{"system":{"statsInboundUplink":false,"StatsInboundUplink":null,"statsInboundDownlink":true}}}`, false},
		{"negative-api-mutation", `{"api":{"services":["HandlerService"]}}`, `{"api":{"services":["StatsService"]}}`, false},
		{"negative-stats-mutation", `{"stats":{"opaque":7}}`, `{"stats":{}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decode := func(text string) map[string]any {
				var value map[string]any
				if err := json.Unmarshal([]byte(text), &value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			source := decode(tc.source)
			before, _ := json.Marshal(source)
			err := callerServiceRootsError(source, decode(tc.effective))
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, tc.accepted, err)
			}
			after, _ := json.Marshal(source)
			if !bytes.Equal(before, after) {
				t.Fatal("assertion mutated the caller source fixture")
			}
		})
	}
}
