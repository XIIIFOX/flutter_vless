package native_dns_preservation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type transportNoneProfile struct {
	Name         string         `json:"name"`
	Config       map[string]any `json:"config"`
	SockoptPaths [][]string     `json:"sockoptPaths"`
}
type transportNoneValue struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Value   any    `json:"value"`
	Core    string `json:"core"`
	ApplyTo string `json:"applyTo"`
}
type transportNoneCases struct {
	Profiles         []transportNoneProfile `json:"profiles"`
	EquivalentValues []transportNoneValue   `json:"equivalentValues"`
	RefusalValues    []transportNoneValue   `json:"refusalValues"`
}

func transportNoneCorpus(t *testing.T) transportNoneCases {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("transport None source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "transport-none.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases transportNoneCases
	if err := json.Unmarshal(data, &cases); err != nil || len(cases.Profiles) != 2 || len(cases.EquivalentValues) != 5 || len(cases.RefusalValues) != 3 {
		t.Fatal("two transport profiles, five equivalent values and three refusals required", err)
	}
	return cases
}

func transportNoneObject(t *testing.T, root any, path []string) map[string]any {
	t.Helper()
	node := root
	for _, component := range path {
		switch object := node.(type) {
		case map[string]any:
			var ok bool
			node, ok = object[component]
			if !ok {
				t.Fatal("missing socket policy path", path)
			}
		case []any:
			index, err := strconv.Atoi(component)
			if err != nil || index < 0 || index >= len(object) {
				t.Fatal("socket policy index out of range")
			}
			node = object[index]
		default:
			t.Fatal("invalid socket policy path", path)
		}
	}
	result, ok := node.(map[string]any)
	if !ok {
		t.Fatal("socket policy object required")
	}
	return result
}

func transportNoneDocument(t *testing.T, profile transportNoneProfile, value transportNoneValue) []byte {
	t.Helper()
	data, err := json.Marshal(profile.Config)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	paths := profile.SockoptPaths
	if value.ApplyTo == "primary" {
		paths = paths[:1]
	}
	for _, path := range paths {
		options := transportNoneObject(t, config, path)
		delete(options, "addressPortStrategy")
		if value.Present {
			options["addressPortStrategy"] = value.Value
		}
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeTransportNone(data []byte) (*core.Config, error) {
	config, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return config.Build()
}

func transportNonePrimaryStrategy(t *testing.T, config *core.Config) internet.AddressPortStrategy {
	t.Helper()
	if len(config.Outbound) == 0 || config.Outbound[0].SenderSettings == nil {
		t.Fatal("missing primary transport sender")
	}
	message, err := config.Outbound[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender, ok := message.(*proxyman.SenderConfig)
	if !ok || sender.StreamSettings == nil || sender.StreamSettings.SocketSettings == nil {
		t.Fatal("missing explicit primary socket settings")
	}
	return sender.StreamSettings.SocketSettings.AddressPortStrategy
}

func rejectTransportNone(t *testing.T, data []byte) {
	t.Helper()
	directory := t.TempDir()
	input, output := filepath.Join(directory, "source.json"), filepath.Join(directory, "effective.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("NATIVE_DNS_PREPARER"), "--prepare-dns-fixture", input, output, loopbackInterface(t), "endpoint.invalid", "127.0.0.1")
	_, err := command.CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatal("socket strategy candidate did not complete an explicit native refusal", err)
	}
	if retained, err := os.ReadFile(input); err != nil || !bytes.Equal(retained, data) {
		t.Fatal("refusal changed source", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal published effective profile", err)
	}
}

// Decode/Build and file-only exporters. No Core instance, resolver or socket.
func testTransportNone(t *testing.T, native bool) {
	cases := transportNoneCorpus(t)
	for _, profile := range cases.Profiles {
		t.Run("transport_none_"+profile.Name, func(t *testing.T) {
			control := transportNoneDocument(t, profile, transportNoneValue{})
			expected, err := decodeTransportNone(control)
			if err != nil {
				t.Fatal(err)
			}
			var nativeExpected *core.Config
			if native {
				prepared := prepareEndpointAddress(t, control)
				encoded, err := json.Marshal(prepared)
				if err != nil {
					t.Fatal(err)
				}
				nativeExpected, err = decodeTransportNone(encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, value := range cases.EquivalentValues {
				t.Run(value.Name, func(t *testing.T) {
					data := transportNoneDocument(t, profile, value)
					built, err := decodeTransportNone(data)
					if err != nil || !proto.Equal(expected, built) {
						t.Fatal("Core-equivalent None value changed compiled profile", err)
					}
					if transportNonePrimaryStrategy(t, built) != internet.AddressPortStrategy_None {
						t.Fatal("equivalent raw value did not compile to explicit None policy")
					}
					if !native {
						return
					}
					effective := prepareEndpointAddress(t, data)
					for _, path := range profile.SockoptPaths {
						options := transportNoneObject(t, effective, path)
						actual, present := options["addressPortStrategy"]
						if present != value.Present || present && !reflect.DeepEqual(actual, value.Value) {
							t.Fatal("native preparation rewrote caller socket strategy", path)
						}
					}
					for _, key := range []string{"dns", "remarks", "custom"} {
						if !reflect.DeepEqual(effective[key], profile.Config[key]) {
							t.Fatal("native preparation changed caller field", key)
						}
					}
					encoded, err := json.Marshal(effective)
					if err != nil {
						t.Fatal(err)
					}
					compiled, err := decodeTransportNone(encoded)
					if err != nil || !proto.Equal(nativeExpected, compiled) {
						t.Fatal("None spelling changed prepared socket/transport/routing policy", err)
					}
					t.Log("TRANSPORT_NONE_EQUIVALENCE_PASS")
				})
			}
			for _, value := range cases.RefusalValues {
				t.Run(value.Name, func(t *testing.T) {
					data := transportNoneDocument(t, profile, value)
					built, err := decodeTransportNone(data)
					if value.Core == "active" && err != nil || value.Core == "invalid" && err == nil {
						t.Fatal("Core refusal/active control changed", err)
					}
					if value.Core == "active" && transportNonePrimaryStrategy(t, built) != internet.AddressPortStrategy_SrvPortOnly {
						t.Fatal("valid active strategy control became None")
					}
					if native {
						rejectTransportNone(t, data)
					}
				})
			}
		})
	}
}
