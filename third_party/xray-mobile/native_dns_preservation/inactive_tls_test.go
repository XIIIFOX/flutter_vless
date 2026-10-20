package native_dns_preservation_test

// Decode/Build and typed-message inspection only. Runtime use is separately
// covered by the existing CI-only XHTTP carrier, never by this helper.
import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func inactiveTLSRawStreams(t *testing.T, config map[string]any) map[string]map[string]any {
	t.Helper()
	for _, raw := range config["outbounds"].([]any) {
		handler := raw.(map[string]any)
		if handler["tag"] != "proxy" {
			continue
		}
		parent := handler["streamSettings"].(map[string]any)
		result := map[string]map[string]any{"primary": parent}
		if settings, ok := parent["xhttpSettings"].(map[string]any); ok {
			if child, ok := settings["downloadSettings"].(map[string]any); ok {
				result["download"] = child
			}
		}
		return result
	}
	t.Fatal("inactive TLS fixture proxy stream missing")
	return nil
}

func inactiveTLSBuiltStreams(t *testing.T, built *core.Config) map[string]*internet.StreamConfig {
	t.Helper()
	parent := transportCallerStream(t, built, "outbounds", "proxy")
	result := map[string]*internet.StreamConfig{"primary": parent}
	for _, transport := range parent.TransportSettings {
		message, err := transport.Settings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if config, ok := message.(*splithttp.Config); ok && config.DownloadSettings != nil {
			result["download"] = config.DownloadSettings
		}
	}
	return result
}

func assertInactiveTLSSecurity(t *testing.T, raw map[string]any, stream *internet.StreamConfig) {
	t.Helper()
	security, _ := raw["security"].(string)
	switch strings.ToLower(security) {
	case "", "none":
		if stream.SecurityType != "" || len(stream.SecuritySettings) != 0 {
			t.Fatal("inactive TLS settings instantiated transport security")
		}
	case "tls", "reality":
		if len(stream.SecuritySettings) != 1 || stream.SecurityType != stream.SecuritySettings[0].Type {
			t.Fatal("active transport security type/settings disagree")
		}
		message, err := stream.SecuritySettings[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(security, "tls") {
			config, ok := message.(*tls.Config)
			if !ok || config.EchConfigList != raw["tlsSettings"].(map[string]any)["echConfigList"] {
				t.Fatal("active inline TLS positive control was not compiled")
			}
		} else if _, ok := message.(*reality.Config); !ok {
			t.Fatal("Reality selected a dormant TLS security config")
		}
	default:
		t.Fatal("unexpected security in inactive TLS fixture")
	}
}

func testInactiveTLS(t *testing.T, native bool) {
	retainedTLSObjects := 0
	for _, tc := range preparationCorpus(t, "inactive-tls.json", 12) {
		t.Run("inactive_tls/"+tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			var effective map[string]any
			if native {
				prepared, _ := prepare(t, tc.Config)
				if err := json.Unmarshal(prepared, &effective); err != nil {
					t.Fatal(err)
				}
				afterPrepare, _ := json.Marshal(tc.Config)
				if !bytes.Equal(source, afterPrepare) {
					t.Fatal("native preparation mutated source TLS fixture")
				}
			} else {
				effective = tc.Config
			}
			data, _ := json.Marshal(effective)
			built, err := schemaFieldsBuild(data)
			if err != nil {
				t.Fatal("inactive TLS fixture failed pinned Core Build", err)
			}
			originalStreams := inactiveTLSRawStreams(t, tc.Config)
			actualStreams := inactiveTLSRawStreams(t, effective)
			compiledStreams := inactiveTLSBuiltStreams(t, built)
			if len(originalStreams) != len(actualStreams) || len(actualStreams) != len(compiledStreams) {
				t.Fatal("typed immediate XHTTP child path was lost")
			}
			control := opaqueClone(t, effective)
			controlStreams := inactiveTLSRawStreams(t, control)
			removed := 0
			for path, original := range originalStreams {
				actual, compiled := actualStreams[path], compiledStreams[path]
				security, securityPresent := original["security"]
				actualSecurity, actualSecurityPresent := actual["security"]
				tlsSettings, tlsPresent := original["tlsSettings"]
				actualTLS, actualTLSPresent := actual["tlsSettings"]
				if actual == nil || compiled == nil || securityPresent != actualSecurityPresent || tlsPresent != actualTLSPresent ||
					!reflect.DeepEqual(security, actualSecurity) || !reflect.DeepEqual(tlsSettings, actualTLS) {
					t.Fatal("caller TLS/security subtree changed", path)
				}
				assertInactiveTLSSecurity(t, actual, compiled)
				if _, present := original["tlsSettings"]; present {
					retainedTLSObjects++
					security, _ := original["security"].(string)
					if !strings.EqualFold(security, "tls") {
						delete(controlStreams[path], "tlsSettings")
						removed++
					}
				}
			}
			if tc.Name == "primary_tls_inline" {
				if removed != 0 {
					t.Fatal("active inline TLS control was treated as dormant")
				}
			} else {
				literal, _ := json.Marshal(control)
				want, err := schemaFieldsBuild(literal)
				if removed != 1 || err != nil || !proto.Equal(built, want) {
					t.Fatal("dormant TLS changed full compiled configuration", err)
				}
			}
			after, err := json.Marshal(tc.Config)
			if err != nil || !bytes.Equal(source, after) {
				t.Fatal("inactive TLS source changed")
			}
		})
	}
	if retainedTLSObjects != 12 {
		t.Fatal("twelve caller TLS objects must be checked", retainedTLSObjects)
	}
}
