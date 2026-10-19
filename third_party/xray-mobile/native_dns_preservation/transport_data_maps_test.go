package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

type transportDataCase struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
	Maps   []struct {
		Path []string `json:"path"`
		Kind string   `json:"kind"`
	} `json:"maps"`
}

// Only Decode/Build, typed-message decoding and file-only native exporters run.
// Header maps in inactive aliases/outer XHTTP settings must also remain data.
func testTransportDataMaps(t *testing.T, native bool) {
	t.Run("transport_data_penetrating_child_socket", func(t *testing.T) { testPenetratingChildSocketData(t, native) })
	t.Run("transport_data_inactive_grandchild", func(t *testing.T) { testXHTTPInactiveGrandchild(t, native) })
	var cases []transportDataCase
	if err := json.Unmarshal(selectorFixture(t, "transport-data-maps.json"), &cases); err != nil || len(cases) != 10 {
		t.Fatal("ten transport dictionary profiles required", err)
	}
	counts := map[string]int{"websocket": 1, "httpupgrade": 1, "xhttp_preferred": 1,
		"splithttp_alias": 1, "xhttp_extra_override_download": 2, "xhttp_direct_download": 2,
		"masque": 1, "tcp_http": 4, "tcp_raw_alias": 2, "hysteria_masquerade": 1}
	for _, tc := range cases {
		t.Run("transport_data_"+tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			want := transportCompiledMaps(t, source, tc.Config)
			if len(want) != counts[tc.Name] {
				t.Fatalf("effective Core header map count: got %d, want %d", len(want), counts[tc.Name])
			}
			for name, value := range want {
				assertTransportHeaderValues(t, name, value)
			}
			if !native {
				return
			}
			prepared, _ := prepare(t, tc.Config)
			var effective map[string]any
			if err := json.Unmarshal(prepared, &effective); err != nil {
				t.Fatal(err)
			}
			for _, dictionary := range tc.Maps {
				if dictionary.Kind != "string" && dictionary.Kind != "string-list" {
					t.Fatal("unknown shared dictionary kind")
				}
				if !reflect.DeepEqual(transportRawMap(t, tc.Config, tc.Config, dictionary.Path),
					transportRawMap(t, effective, tc.Config, dictionary.Path)) {
					t.Fatalf("native preparation changed caller dictionary at %v", dictionary.Path)
				}
			}
			if !reflect.DeepEqual(want, transportCompiledMaps(t, prepared, tc.Config)) {
				t.Fatal("native preparation changed effective compiled Core header maps")
			}
			retained, err := json.Marshal(tc.Config)
			if err != nil || !bytes.Equal(source, retained) {
				t.Fatal("caller source changed", err)
			}
		})
	}
}

func testXHTTPInactiveGrandchild(t *testing.T, native bool) {
	var cases []transportDataCase
	if err := json.Unmarshal(selectorFixture(t, "transport-data-maps.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if tc.Name != "xhttp_direct_download" {
			continue
		}
		stream := tc.Config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		child := stream["xhttpSettings"].(map[string]any)["downloadSettings"].(map[string]any)
		childSettings := child["xhttpSettings"].(map[string]any)
		childSettings["mode"] = "packet-up"
		dormant := map[string]any{"address": "127.0.0.1", "port": float64(9443), "network": "tcp"}
		childSettings["downloadSettings"] = dormant
		source, _ := json.Marshal(tc.Config)
		data := source
		if native {
			data, _ = prepare(t, tc.Config)
			var effective map[string]any
			if err := json.Unmarshal(data, &effective); err != nil {
				t.Fatal(err)
			}
			actualStream := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
			actualChild := actualStream["xhttpSettings"].(map[string]any)["downloadSettings"].(map[string]any)
			if !reflect.DeepEqual(actualChild["xhttpSettings"], childSettings) {
				t.Fatal("native preparation changed the immediate client's inactive download")
			}
		}
		decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		built, err := decoded.Build()
		if err != nil {
			t.Fatal(err)
		}
		memory, err := internet.ToMemoryStreamConfig(transportCallerStream(t, built, "outbounds", "caller-transport"))
		if err != nil {
			t.Fatal(err)
		}
		download, err := internet.ToMemoryStreamConfig(memory.ProtocolSettings.(*splithttp.Config).DownloadSettings)
		if err != nil {
			t.Fatal(err)
		}
		grandchild := download.ProtocolSettings.(*splithttp.Config).DownloadSettings
		if grandchild == nil || grandchild.ProtocolName != "tcp" || grandchild.Port != 9443 ||
			grandchild.Address.AsAddress().String() != "127.0.0.1" {
			t.Fatal("Core did not retain the inert TCP grandchild configuration")
		}
		retained, _ := json.Marshal(tc.Config)
		if !bytes.Equal(source, retained) {
			t.Fatal("caller source changed")
		}
		return
	}
	t.Fatal("direct XHTTP fixture missing")
}

// The actual dialer applies inheritance later. This inert check preserves both
// compiled policies and the original dormant JSON; it does not emulate Dial.
func testPenetratingChildSocketData(t *testing.T, native bool) {
	var source map[string]any
	for _, candidate := range protocolCorpus(t) {
		if candidate.Name == "vless_xhttp_penetrating_download" {
			data, _ := json.Marshal(candidate.Config)
			if err := json.Unmarshal(data, &source); err != nil {
				t.Fatal(err)
			}
		}
	}
	if source == nil {
		t.Fatal("penetrating source fixture missing")
	}
	stream := source["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	child := stream["xhttpSettings"].(map[string]any)["extra"].(map[string]any)["downloadSettings"].(map[string]any)
	child["sockopt"].(map[string]any)["addressPortStrategy"] = "srvportonly"
	original, _ := json.Marshal(source)
	data := original
	if native {
		data, _ = prepare(t, source)
		var effective map[string]any
		if err := json.Unmarshal(data, &effective); err != nil {
			t.Fatal(err)
		}
		assertPenetratingXHTTPGraph(t, source, effective)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal("dormant child SRV policy must remain Core-valid", err)
	}
	parent, err := internet.ToMemoryStreamConfig(transportCallerStream(t, built, "outbounds", "proxy"))
	if err != nil {
		t.Fatal(err)
	}
	download, err := internet.ToMemoryStreamConfig(parent.ProtocolSettings.(*splithttp.Config).DownloadSettings)
	if err != nil {
		t.Fatal(err)
	}
	if parent.SocketSettings == nil || !parent.SocketSettings.Penetrate || parent.SocketSettings.TcpKeepAliveIdle != 30 ||
		parent.SocketSettings.AddressPortStrategy != internet.AddressPortStrategy_None ||
		download.SocketSettings == nil || download.SocketSettings.TcpKeepAliveIdle != 7 ||
		download.SocketSettings.AddressPortStrategy != internet.AddressPortStrategy_SrvPortOnly ||
		download.SocketSettings.DialerProxy != "dormant-download-handler" {
		t.Fatal("Core compiled parent or dormant child socket policy changed")
	}
	retained, _ := json.Marshal(source)
	if !bytes.Equal(original, retained) {
		t.Fatal("dormant child source changed")
	}
}

func transportRawMap(t *testing.T, document, original map[string]any, path []string) any {
	t.Helper()
	if len(path) < 3 {
		t.Fatal("shared header path is incomplete")
	}
	index, err := strconv.Atoi(path[1])
	if err != nil {
		t.Fatal(err)
	}
	tag := original[path[0]].([]any)[index].(map[string]any)["tag"]
	var value any
	for _, item := range document[path[0]].([]any) {
		if item.(map[string]any)["tag"] == tag {
			if value != nil {
				t.Fatal("ambiguous caller handler tag")
			}
			value = item
		}
	}
	for _, field := range path[2:] {
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("missing shared header path %v", path)
		}
		value, ok = object[field]
		if !ok {
			t.Fatalf("missing shared header path %v", path)
		}
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatal("shared header path must select a dictionary")
	}
	return value
}

func transportCompiledMaps(t *testing.T, data []byte, original map[string]any) map[string]any {
	t.Helper()
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal("transport profile is not valid pinned Core JSON", err)
	}
	result := map[string]any{}
	for _, side := range []string{"inbounds", "outbounds"} {
		for index, item := range original[side].([]any) {
			tag := item.(map[string]any)["tag"].(string)
			stream := transportCallerStream(t, built, side, tag)
			collectTransportMaps(t, result, fmt.Sprintf("%s/%d", side, index), stream)
		}
	}
	return result
}

func transportCallerStream(t *testing.T, built *core.Config, side, tag string) *internet.StreamConfig {
	t.Helper()
	if side == "inbounds" {
		for _, handler := range built.Inbound {
			if handler.Tag == tag {
				message, err := handler.ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				return message.(*proxyman.ReceiverConfig).StreamSettings
			}
		}
	} else {
		for _, handler := range built.Outbound {
			if handler.Tag == tag {
				message, err := handler.SenderSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				return message.(*proxyman.SenderConfig).StreamSettings
			}
		}
	}
	t.Fatalf("caller handler missing: %s", tag)
	return nil
}

func collectTransportMaps(t *testing.T, result map[string]any, prefix string, stream *internet.StreamConfig) {
	t.Helper()
	if stream == nil {
		return
	}
	for _, transport := range stream.TransportSettings {
		message, err := transport.Settings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		name := prefix + "/" + transport.ProtocolName
		switch value := message.(type) {
		case *websocket.Config:
			result[name] = value.Header
		case *httpupgrade.Config:
			result[name] = value.Header
		case *masque.Config:
			result[name] = value.Headers
		case *hysteria.Config:
			result[name] = value.MasqStringHeaders
		case *splithttp.Config:
			result[name] = value.Headers
			collectTransportMaps(t, result, name+"/download", value.DownloadSettings)
		case *tcp.Config:
			if value.HeaderSettings == nil {
				continue
			}
			message, err := value.HeaderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if http, ok := message.(*httpheader.Config); ok {
				for side, headers := range map[string][]*httpheader.Header{"request": http.Request.Header, "response": http.Response.Header} {
					values := map[string][]string{}
					for _, header := range headers {
						values[header.Name] = header.Value
					}
					result[name+"/"+side] = values
				}
			}
		}
	}
}

func assertTransportHeaderValues(t *testing.T, name string, value any) {
	t.Helper()
	for key, want := range map[string]string{"allowInsecure": "literal-header-value", "network": "MiXeD-CaSe",
		"xHTTPSettings": "literal-alias-name", "type": "xicmp", "Origin": "quic+local://literal.invalid"} {
		switch headers := value.(type) {
		case map[string]string:
			if headers[key] != want {
				t.Fatalf("Core compiled header dictionary changed at %s/%s", name, key)
			}
		case map[string][]string:
			expected := []string{want}
			if key == "network" || key == "xHTTPSettings" {
				expected = append(expected, "second-list-value")
			}
			if !reflect.DeepEqual(headers[key], expected) {
				t.Fatalf("Core compiled HTTP string-list changed at %s/%s", name, key)
			}
		default:
			t.Fatal("unrecognized compiled header map")
		}
	}
}
