package XRay

import (
	"bytes"
	"net"
	"strconv"
	"testing"
)

func TestPreflightUsesPinnedCoreWithoutBinding(t *testing.T) {
	// Keep the requested port occupied. A check must still succeed because it
	// validates a document instead of attempting to start its listeners.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := []byte(`{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":` + strconv.Itoa(port) + `}],"outbounds":[{"protocol":"freedom"}]}`)
	original := append([]byte(nil), config...)
	before := coreInstance
	if code := CheckPrivate(config); code != 0 {
		t.Fatalf("valid Core config: code %d", code)
	}
	if coreInstance != before {
		t.Fatal("Preflight replaced the active runtime")
	}
	if !bytes.Equal(config, original) {
		t.Fatal("Preflight changed the caller's document")
	}
	if code := CheckPrivate([]byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"},{"protocol":"private-error-canary"}]}`)); code != 3|(2<<8)|(2<<16) {
		t.Fatalf("outbound location: %d", code)
	}
	if code := CheckPrivate([]byte(`{"inbounds":[{"protocol":"private-error-canary","port":10808}],"outbounds":[{"protocol":"freedom"}]}`)); code != 3|(1<<8)|(1<<16) {
		t.Fatalf("inbound location: %d", code)
	}
	if CheckPrivate([]byte(`not-json`)) != 1 {
		t.Fatal("invalid JSON must fail without starting Core")
	}
}

func TestPreflightReportsClosedStages(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want int64
	}{
		{"empty-document", `{}`, 0},
		{"null", `null`, 1},
		{"ambiguous-policy", `{"log":{},"LOG":{}}`, 1},
		{"port-type", `{"inbounds":[{"protocol":"socks","port":true}]}`, 2},
		{"missing-certificate", `{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/missing/private-canary.pem","keyFile":"/missing/private-canary.key"}]}}}]}`, 3 | (2 << 8) | (1 << 16)},
		{"custom-network", `{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"private-canary"}}]}`, 3 | (2 << 8) | (1 << 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckPrivate([]byte(tc.json)); got != tc.want {
				t.Fatalf("closed result: got %d, want %d", got, tc.want)
			}
		})
	}
}
