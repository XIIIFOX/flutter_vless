package native_dns_preservation_test

import (
	"reflect"
	"testing"
)

func assertPenetratingXHTTPGraph(t *testing.T, source, effective map[string]any) {
	t.Helper()
	sourceStream := source["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	stream := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if !reflect.DeepEqual(sourceStream["xhttpSettings"], stream["xhttpSettings"]) {
		t.Fatal("penetrating XHTTP changed the download or HTTP/TLS settings")
	}
	options := stream["sockopt"].(map[string]any)
	if options["penetrate"] != true || options["tcpKeepAliveIdle"] != float64(30) || options["domainStrategy"] != "AsIs" {
		t.Fatal("penetrating parent lost the shared socket policy")
	}
	handlers := map[string]map[string]any{}
	loops := 0
	for _, value := range effective["outbounds"].([]any) {
		outbound := value.(map[string]any)
		tag, _ := outbound["tag"].(string)
		handlers[tag] = outbound
		if outbound["protocol"] == "loopback" {
			loops++
		}
	}
	loop, ok := handlers[options["dialerProxy"].(string)]
	if !ok || loop["protocol"] != "loopback" || loops != 1 {
		t.Fatal("upload and download require exactly one parent private context")
	}
	scope := loop["settings"].(map[string]any)["inboundTag"].(string)
	ports := map[string]bool{}
	closed := false
	for _, value := range effective["routing"].(map[string]any)["rules"].([]any) {
		rule := value.(map[string]any)
		if !reflect.DeepEqual(rule["inboundTag"], []any{scope}) {
			continue
		}
		if closed {
			t.Fatal("private scope has rules after its terminal denial")
		}
		outbound := handlers[rule["outboundTag"].(string)]
		if outbound["protocol"] == "blackhole" {
			if len(rule) != 3 {
				t.Fatal("private scope denial is not an unconditional catchall")
			}
			closed = true
			continue
		}
		port, _ := rule["port"].(string)
		if (port != "443" && port != "8443") || ports[port] ||
			!reflect.DeepEqual(rule["domain"], []any{"full:endpoint.invalid"}) || outbound["protocol"] != "freedom" {
			t.Fatal("shared context did not contain only the two exact destination pins")
		}
		ports[port] = true
		if outbound["settings"].(map[string]any)["redirect"] != "127.0.0.1:0" {
			t.Fatal("XHTTP pin did not use the independently resolved numeric endpoint")
		}
		physical := outbound["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
		if physical["tcpKeepAliveIdle"] != float64(30) || physical["penetrate"] != true || physical["dialerProxy"] != nil {
			t.Fatal("XHTTP physical leaf lost the parent options or retained a dialer cycle")
		}
	}
	if !closed || len(ports) != 2 {
		t.Fatal("XHTTP shared context is incomplete or can fall through to caller routing")
	}
}
