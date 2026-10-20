package native_dns_preservation_test

// Static Core Build plus file-only native exporters. A loopback redispatches
// its link and never uses its sender's socket chain; real traffic is separate.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/loopback"
	"google.golang.org/protobuf/proto"
)

type loopbackChainCase struct {
	Name                   string         `json:"name"`
	Config                 map[string]any `json:"config"`
	ExpectedNativeAccepted bool           `json:"expectedNativeAccepted"`
}

func loopbackChainHandler(t *testing.T, config *core.Config, tag string) *core.OutboundHandlerConfig {
	t.Helper()
	var found *core.OutboundHandlerConfig
	for _, handler := range config.Outbound {
		if handler.Tag == tag {
			if found != nil {
				t.Fatal("ambiguous loopback fixture tag")
			}
			found = handler
		}
	}
	return found
}

func loopbackNativeCandidate(t *testing.T, source []byte) ([]byte, bool) {
	t.Helper()
	directory := t.TempDir()
	input, output := filepath.Join(directory, "source.json"), filepath.Join(directory, "effective.json")
	if err := os.WriteFile(input, source, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("NATIVE_DNS_PREPARER"), "--prepare-dns-fixture",
		input, output, loopbackInterface(t), "endpoint.invalid", "127.0.0.1")
	if _, err := command.CombinedOutput(); err != nil {
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatal("native loopback candidate did not return an explicit preparation outcome", err)
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused loopback candidate published an effective profile", err)
		}
		if retained, err := os.ReadFile(input); err != nil || !bytes.Equal(retained, source) {
			t.Fatal("refused loopback candidate changed source", err)
		}
		return nil, false
	}
	if retained, err := os.ReadFile(input); err != nil || !bytes.Equal(retained, source) {
		t.Fatal("native loopback preparation changed source", err)
	}
	prepared, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return prepared, true
}

func testLoopbackChains(t *testing.T, native bool) {
	var cases []loopbackChainCase
	if err := json.Unmarshal(selectorFixture(t, "loopback-chains.json"), &cases); err != nil || len(cases) != 6 {
		t.Fatal("six loopback socket-chain profiles required", err)
	}
	accepted := 0
	for _, tc := range cases {
		t.Run("loopback_chain/"+tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			original, err := schemaFieldsBuild(source)
			if err != nil {
				t.Fatal("loopback source, including native graph refusal controls, must build with pinned Core", err)
			}
			loop := loopbackChainHandler(t, original, "caller-loop")
			if tc.Name == "missing_referenced_loop" {
				primary := transportCallerStream(t, original, "outbounds", "proxy")
				if loop != nil || primary.SocketSettings == nil || primary.SocketSettings.DialerProxy != "caller-loop" {
					t.Fatal("missing-loop native refusal control lost its compiled reference")
				}
			} else {
				if loop == nil {
					t.Fatal("missing typed loopback positive/control sender")
				}
				message, err := loop.ProxySettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				config, ok := message.(*loopback.Config)
				if !ok || config.InboundTag != "caller-loop-input" {
					t.Fatal("Core did not retain typed loopback redispatch settings")
				}
				stream := transportCallerStream(t, original, "outbounds", "caller-loop")
				if stream.SocketSettings == nil || stream.SocketSettings.DialerProxy == "" ||
					stream.SocketSettings.TcpKeepAliveIdle != 7 || len(stream.SecuritySettings) != 1 {
					t.Fatal("dormant loopback sender control was not actually compiled")
				}
			}
			if !native {
				return
			}
			prepared, admitted := loopbackNativeCandidate(t, source)
			if admitted != tc.ExpectedNativeAccepted {
				t.Fatal("native active-chain admission differs from shared expectation", admitted, tc.ExpectedNativeAccepted)
			}
			if !admitted {
				return
			}
			accepted++
			built, err := schemaFieldsBuild(prepared)
			if err != nil {
				t.Fatal("native loopback preparation broke pinned Core configuration", err)
			}
			actualLoop := loopbackChainHandler(t, built, "caller-loop")
			if loop == nil || actualLoop == nil || !proto.Equal(loop.ProxySettings, actualLoop.ProxySettings) || !proto.Equal(loop.SenderSettings, actualLoop.SenderSettings) {
				t.Fatal("native preparation changed typed dormant loopback settings or sender")
			}
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			var want, got any
			for _, raw := range tc.Config["outbounds"].([]any) {
				if raw.(map[string]any)["tag"] == "caller-loop" {
					want = raw
				}
			}
			for _, raw := range effective["outbounds"].([]any) {
				if raw.(map[string]any)["tag"] == "caller-loop" {
					got = raw
				}
			}
			if want == nil || !reflect.DeepEqual(want, got) || !reflect.DeepEqual(tc.Config["dns"], effective["dns"]) {
				t.Fatal("native preparation changed exact loopback JSON or caller DNS")
			}
			wantRules := tc.Config["routing"].(map[string]any)["rules"].([]any)
			actualRules := effective["routing"].(map[string]any)["rules"].([]any)
			if len(actualRules) < len(wantRules) || !reflect.DeepEqual(actualRules[len(actualRules)-len(wantRules):], wantRules) {
				t.Fatal("loopback redispatch caller routing rule changed")
			}
			after, _ := json.Marshal(tc.Config)
			if !bytes.Equal(source, after) {
				t.Fatal("loopback source map mutated")
			}
		})
	}
	if native && accepted != 3 {
		t.Fatal("three positive loopback profiles must reach typed and whole-JSON checks", accepted)
	}
}
