package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

// Actual JSON decode and protobuf Build only; no Core instance or listeners.
func TestSchemaFieldsPreparation(t *testing.T) {
	const literal = `{"dns":{"servers":["tcp://9.9.9.9"],"queryStrategy":"UseIPv4"},"inbounds":[{"protocol":"http","listen":"127.0.0.1","port":10807,"tag":"caller-http","settings":{}}],"outbounds":[{"protocol":"socks","tag":"proxy","settings":{"servers":[{"address":"198.51.100.7","port":19090}]},"streamSettings":{"network":"tcp"}},{"protocol":"freedom","tag":"direct","settings":{}},{"protocol":"blackhole","tag":"block","settings":{}}]}`
	want, err := schemaFieldsBuild([]byte(literal))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name          string         `json:"name"`
		Config        map[string]any `json:"config"`
		CoreInvalid   bool           `json:"coreInvalid"`
		InvalidSyntax bool           `json:"invalidSyntax"`
	}
	if err := json.Unmarshal(selectorFixture(t, "schema-fields.json"), &cases); err != nil || len(cases) != 5 {
		t.Fatal("five schema field cases required", err)
	}
	positive, negative := 0, 0
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			decoded, decodeErr := serial.DecodeJSONConfig(bytes.NewReader(source))
			if tc.InvalidSyntax && decodeErr == nil {
				t.Fatal("nonstring transport unexpectedly decoded")
			}
			var actual *core.Config
			if decodeErr == nil {
				actual, err = decoded.Build()
			} else {
				err = decodeErr
			}
			if tc.CoreInvalid {
				negative++
				if err == nil {
					t.Fatal("active invalid transport unexpectedly built")
				}
				return // Native preparation is not a replacement for Core validation.
			}
			positive++
			if err != nil || !proto.Equal(want, actual) {
				t.Fatal("schema spelling or dormant network changed compiled Core configuration", err)
			}
			if os.Getenv("NATIVE_DNS_PREPARER") != "" {
				t.Run("WindowsPreparer", func(t *testing.T) { schemaFieldsNative(t, tc.Config, actual) })
				if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
					t.Run("ApplePreparer", func(t *testing.T) {
						t.Setenv("NATIVE_DNS_PREPARER", apple)
						schemaFieldsNative(t, tc.Config, actual)
					})
				}
			}
			retained, err := json.Marshal(tc.Config)
			if err != nil || !bytes.Equal(retained, source) {
				t.Fatal("source schema fields changed", err)
			}
		})
	}
	if positive != 3 || negative != 2 {
		t.Fatal("schema field positive/negative corpus changed")
	}
}

func schemaFieldsBuild(data []byte) (*core.Config, error) {
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return decoded.Build()
}

func schemaFieldsNative(t *testing.T, source map[string]any, caller *core.Config) {
	t.Helper()
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	// The existing generic exporter helper accepts raw schema spelling; prepare
	// intentionally assumes canonical keys for its older DNS/proxy assertions.
	effective := prepareEndpointAddress(t, data)
	prepared, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	built, err := schemaFieldsBuild(prepared)
	if err != nil {
		t.Fatal("native prepared configuration failed Core Build", err)
	}
	if len(built.Outbound) < 3 || built.Outbound[0].Tag != "proxy" {
		t.Fatal("native preparation changed the caller default outbound")
	}
	if !proto.Equal(built.Outbound[0].ProxySettings, caller.Outbound[0].ProxySettings) {
		t.Fatal("native preparation changed the typed caller proxy settings")
	}
	for key, dns := range source {
		if strings.EqualFold(key, "dns") && !reflect.DeepEqual(effective["dns"], dns) {
			t.Fatal("native preparation changed caller DNS")
		}
	}
	found := false
	for _, inbound := range built.Inbound {
		message, err := inbound.ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		ports := message.(*proxyman.ReceiverConfig).PortList.Ports()
		if inbound.Tag == "caller-http" {
			if found || !reflect.DeepEqual(ports, []uint32{10807}) {
				t.Fatal("native preparation changed the imported HTTP listener")
			}
			found = true
		} else {
			for _, port := range ports {
				if port == 10807 {
					t.Fatal("private listener collided with the imported HTTP listener")
				}
			}
		}
	}
	if !found {
		t.Fatal("native preparation lost the imported HTTP listener")
	}
}
