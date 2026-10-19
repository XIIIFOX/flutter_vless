package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	manager "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	configserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport"
)

type selectorCase struct {
	Name          string         `json:"name"`
	Config        map[string]any `json:"config"`
	Requests      []string       `json:"requests"`
	Expected      []string       `json:"expected"`
	Prefixes      []string       `json:"prefixes"`
	OriginalTags  []string       `json:"originalTags"`
	FullIsolation bool           `json:"fullIsolation"`
}

func selectorFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("selector fixture source location unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Inert handlers exercise the actual pinned Manager.Select and its cache
// invalidation. No Core instance, Start, Dispatch, socket or worker exists.
type selectorHandler struct{ tag string }

func (*selectorHandler) Start() error                         { panic("selector fixture must not start handlers") }
func (*selectorHandler) Close() error                         { return nil }
func (h *selectorHandler) Tag() string                        { return h.tag }
func (*selectorHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*selectorHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (*selectorHandler) Dispatch(context.Context, *transport.Link) {
	panic("selector fixture must not dispatch")
}

func selectorManager(t *testing.T, tags []string) *manager.Manager {
	t.Helper()
	m, err := manager.New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tag := range tags {
		if err := m.AddHandler(context.Background(), &selectorHandler{tag}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func selectorGroups(t *testing.T, data []byte) ([][]string, []string) {
	t.Helper()
	var schema struct {
		Routing *struct {
			Balancers []struct {
				Selector conf.StringList `json:"selector"`
			} `json:"balancers"`
		} `json:"routing"`
		Observatory *conf.ObservatoryConfig      `json:"observatory"`
		Burst       *conf.BurstObservatoryConfig `json:"burstObservatory"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	groups, prefixes := [][]string{}, []string{}
	if schema.Routing != nil {
		for _, balancer := range schema.Routing.Balancers {
			groups = append(groups, balancer.Selector)
		}
	}
	if schema.Observatory != nil && len(schema.Observatory.SubjectSelector) != 0 {
		groups = append(groups, schema.Observatory.SubjectSelector)
	}
	if schema.Burst != nil && len(schema.Burst.SubjectSelector) != 0 {
		groups = append(groups, schema.Burst.SubjectSelector)
	}
	seen := map[string]bool{}
	for _, group := range groups {
		for _, prefix := range group {
			if prefix != "" && !seen[prefix] {
				prefixes = append(prefixes, prefix)
				seen[prefix] = true
			}
		}
	}
	return groups, prefixes
}

func assertSelectorManagerIsolation(t *testing.T, original, private []string, groups [][]string, prefixes []string) {
	t.Helper()
	before, after := selectorManager(t, original), selectorManager(t, original)
	want := make([][]string, len(groups))
	for index, group := range groups {
		want[index] = before.Select(group)
	}
	for _, tag := range private {
		if err := after.AddHandler(context.Background(), &selectorHandler{tag}); err != nil {
			t.Fatal(err)
		}
		if after.GetHandler(tag) == nil {
			t.Fatal("private tag lost explicit routing access")
		}
	}
	for index, group := range groups {
		if got := after.Select(group); !reflect.DeepEqual(got, want[index]) {
			t.Fatalf("private handlers changed actual Core selection: %q != %q", got, want[index])
		}
	}
	// Keep source selectors, including their cache keys, rather than freezing a
	// list of source handlers: subsequent HandlerService-style adds must work.
	for index, prefix := range prefixes {
		tag := fmt.Sprintf("%s-late-public-%d", prefix, index)
		for _, m := range []*manager.Manager{before, after} {
			if err := m.AddHandler(context.Background(), &selectorHandler{tag}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, group := range groups {
		if !reflect.DeepEqual(after.Select(group), before.Select(group)) {
			t.Fatal("dynamic public additions or selector cache semantics changed")
		}
	}
	if before.GetDefaultHandler().Tag() != after.GetDefaultHandler().Tag() {
		t.Fatal("private handlers changed the caller default")
	}
}

func TestNativeSelectorPrefixAllocation(t *testing.T) {
	var cases []selectorCase
	if err := json.Unmarshal(selectorFixture(t, "selector-prefixes.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 9 {
		t.Fatal("expected nine shared allocator cases")
	}
	preparers := map[string]string{"Windows": os.Getenv("NATIVE_DNS_PREPARER")}
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		preparers["Apple"] = apple
	}
	for name, binary := range preparers {
		t.Run(name, func(t *testing.T) {
			if binary == "" {
				t.Fatal("file-only production tag allocator required")
			}
			for _, tc := range cases {
				t.Run(tc.Name, func(t *testing.T) {
					input, err := json.Marshal(tc)
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					source, output := filepath.Join(dir, "source.json"), filepath.Join(dir, "tags.json")
					if err := os.WriteFile(source, input, 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if result, err := exec.CommandContext(ctx, binary, "--allocate-service-tags-fixture", source, output).CombinedOutput(); err != nil {
						t.Fatalf("tag exporter failed: %v: %s", err, result)
					}
					unchanged, err := os.ReadFile(source)
					if err != nil || !bytes.Equal(input, unchanged) {
						t.Fatal("source fixture changed", err)
					}
					data, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					var tags []string
					if err := json.Unmarshal(data, &tags); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(tags, tc.Expected) {
						t.Fatalf("tag names differ: %q != %q", tags, tc.Expected)
					}
					config, err := json.Marshal(tc.Config)
					if err != nil {
						t.Fatal(err)
					}
					groups, prefixes := selectorGroups(t, config)
					if !reflect.DeepEqual(prefixes, tc.Prefixes) {
						t.Fatal("fixture differs from Core's typed selector parsing")
					}
					for _, tag := range tags {
						for _, prefix := range prefixes {
							if strings.HasPrefix(tag, prefix) {
								t.Fatal("private tag still matches caller prefix")
							}
						}
					}
					if tc.FullIsolation {
						assertSelectorManagerIsolation(t, tc.OriginalTags, tags, groups, prefixes)
					}
				})
			}
		})
	}
}

func selectorTrafficProfile(t *testing.T) map[string]any {
	t.Helper()
	var source map[string]any
	if err := json.Unmarshal(selectorFixture(t, "selector-traffic.json"), &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func testSelectorTrafficPreparation(t *testing.T, native bool) {
	t.Helper()
	t.Run("private_tags_outside_caller_balancer_prefix", func(t *testing.T) {
		source := selectorTrafficProfile(t)
		data, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		if native {
			data, _ = prepare(t, source)
			var effective map[string]any
			if err := json.Unmarshal(data, &effective); err != nil {
				t.Fatal(err)
			}
			want := source["routing"].(map[string]any)["balancers"]
			if !reflect.DeepEqual(want, effective["routing"].(map[string]any)["balancers"]) {
				t.Fatal("caller balancer was rewritten")
			}
			original, private := []string{}, []string{}
			for _, item := range source["outbounds"].([]any) {
				original = append(original, item.(map[string]any)["tag"].(string))
			}
			for _, item := range effective["outbounds"].([]any)[len(original):] {
				private = append(private, item.(map[string]any)["tag"].(string))
			}
			assertSelectorManagerIsolation(t, original, private, [][]string{{"flutter-vless"}}, []string{"flutter-vless"})
		}
		decoded, err := configserial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoded.Build(); err != nil {
			t.Fatal(err)
		}
	})
}
