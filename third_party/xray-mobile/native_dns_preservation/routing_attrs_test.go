package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

func TestRoutingAttrsBuilds(t *testing.T) { testRoutingAttrsData(t, false) }

func TestNativeRoutingAttrsPreservation(t *testing.T) {
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production native preparer required")
	}
	t.Run("WindowsPreparer", func(t *testing.T) { testRoutingAttrsData(t, true) })
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		t.Run("ApplePreparer", func(t *testing.T) {
			t.Setenv("NATIVE_DNS_PREPARER", apple)
			testRoutingAttrsData(t, true)
		})
	}
}

// BuildCondition executes Core's actual AttributeMatcher with inert session
// metadata. No Core instance, router workers, resolver or socket is created.
func testRoutingAttrsData(t *testing.T, native bool) {
	var fixture protocolCase
	if err := json.Unmarshal(selectorFixture(t, "routing-attrs.json"), &fixture); err != nil || fixture.Name != "routing_attribute_dictionary" {
		t.Fatal("routing attribute fixture required", err)
	}
	source, err := json.Marshal(fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	want := routingAttrsCompiledRule(t, source)
	assertRoutingAttrsMatch(t, want)
	if !native {
		return
	}
	prepared, _ := prepare(t, fixture.Config)
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	var actualAttrs any
	for _, entry := range effective["routing"].(map[string]any)["rules"].([]any) {
		if attrs, present := entry.(map[string]any)["attrs"]; present {
			if actualAttrs != nil {
				t.Fatal("caller attribute rule became ambiguous")
			}
			actualAttrs = attrs
		}
	}
	expected := fixture.Config["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)["attrs"]
	if !reflect.DeepEqual(actualAttrs, expected) {
		t.Fatal("native preparation changed caller attribute dictionary")
	}
	actual := routingAttrsCompiledRule(t, prepared)
	if !proto.Equal(want, actual) {
		t.Fatal("native preparation changed the compiled caller attribute rule")
	}
	assertRoutingAttrsMatch(t, actual)
	retained, err := json.Marshal(fixture.Config)
	if err != nil || !bytes.Equal(retained, source) {
		t.Fatal("caller attribute source changed", err)
	}
}

func routingAttrsCompiledRule(t *testing.T, data []byte) *router.RoutingRule {
	t.Helper()
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range built.App {
		message, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if config, ok := message.(*router.Config); ok {
			for _, rule := range config.Rule {
				if len(rule.Attributes) != 0 {
					if len(rule.Attributes) != 5 || rule.GetTag() != "direct" {
						t.Fatal("typed caller attribute rule lost fields")
					}
					return rule
				}
			}
		}
	}
	t.Fatal("compiled routing attribute rule missing")
	return nil
}

func assertRoutingAttrsMatch(t *testing.T, rule *router.RoutingRule) {
	t.Helper()
	condition, err := rule.BuildCondition()
	if err != nil {
		t.Fatal(err)
	}
	attributes := map[string]string{"ALLOWINSECURE": "required", "NETWORK": "MiXeD", "XHTTPSETTINGS": "Alias", "TYPE": "xicmp", "ORIGIN": "quiclocal://literal.invalid"}
	ctx := routingContextRequest("caller-input", false)
	ctx.Content.Attributes = attributes
	if !condition.Apply(ctx) {
		t.Fatal("Core must fold attribute keys while preserving case-sensitive regex values")
	}
	for key, value := range map[string]string{"NETWORK": "mixed", "XHTTPSETTINGS": "alias", "ALLOWINSECURE": "Required", "ORIGIN": "quic+local://literal.invalid"} {
		before := attributes[key]
		attributes[key] = value
		if condition.Apply(ctx) {
			t.Fatalf("Core changed the caller regex semantics for %s", key)
		}
		attributes[key] = before
	}
	delete(attributes, "ALLOWINSECURE")
	if condition.Apply(ctx) {
		t.Fatal("missing required attribute matched")
	}
}
