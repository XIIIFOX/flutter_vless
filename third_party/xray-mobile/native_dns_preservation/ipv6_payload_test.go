package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/blackhole"
	xdns "github.com/xtls/xray-core/proxy/dns"
)

// The first payload slice keeps the transport bootstrap on IPv4. Source DNS
// policy remains authoritative for A/AAAA, including an explicit UseIPv4.
// This file only prepares JSON and builds protobuf configuration, without a
// Core instance, DNS lookup, TUN, network listener or platform route operation.
func testIPv6PayloadPreparation(t *testing.T, native bool) {
	for _, tc := range preparationCorpus(t, "ipv6-payload.json", 2) {
		t.Run(tc.Name, func(t *testing.T) {
			document, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			if native {
				document, _ = prepare(t, tc.Config) // Also requires unchanged caller DNS.
			}
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(document))
			if err != nil {
				t.Fatal(err)
			}
			built, err := decoded.Build()
			if err != nil {
				t.Fatal(err)
			}
			if !native {
				return
			}
			var failures []string
			relays := 0
			blockedTags := make(map[string]bool)
			for _, output := range built.Outbound {
				settings, err := output.ProxySettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				if _, blocked := settings.(*blackhole.Config); blocked {
					blockedTags[output.Tag] = true
				}
				relay, ok := settings.(*xdns.Config)
				if !ok {
					continue
				}
				relays++
				for _, kind := range []int32{1, 28, 15} {
					// Evaluate Core's first matching DNS rule, including catchalls.
					action, code := xdns.RuleAction_Hijack, int32(0)
					for _, rule := range relay.Rule {
						matches := len(rule.QType) == 0
						for _, allowed := range rule.QType {
							matches = matches || allowed == kind
						}
						if matches {
							action, code = rule.Action, int32(rule.RCode)
							break
						}
					}
					if kind != 15 && action != xdns.RuleAction_Hijack {
						failures = append(failures, "private DNS must delegate A and AAAA to the unchanged caller root")
					}
					if kind == 15 && (action != xdns.RuleAction_Return || code != 5) {
						failures = append(failures, "non-address DNS must remain REFUSED without a direct fallback")
					}
				}
			}
			if relays != 1 {
				t.Fatal("one private address-DNS relay required")
			}
			var effective map[string]any
			if err := json.Unmarshal(document, &effective); err != nil {
				t.Fatal(err)
			}
			managed := effective["inbounds"].([]any)[0].(map[string]any)["tag"]
			for _, value := range effective["routing"].(map[string]any)["rules"].([]any) {
				rule := value.(map[string]any)
				ips, _ := rule["ip"].([]any)
				inputs, _ := rule["inboundTag"].([]any)
				applies := len(inputs) == 0
				for _, input := range inputs {
					applies = applies || input == managed
				}
				for _, ip := range ips {
					outbound, _ := rule["outboundTag"].(string)
					if applies && ip == "::/0" && blockedTags[outbound] {
						failures = append(failures, "private IPv6 payload is blocked before caller routing")
					}
				}
			}
			for _, failure := range failures {
				t.Error(failure)
			}
		})
	}
}
