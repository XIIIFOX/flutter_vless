package internet_test

import (
	"errors"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
)

// Decoder/build coverage only. No Core instance/transport/socket is started.
func TestNativeDNSCanonicalKCPAliasesRemainExplicitlyUnsupported(t *testing.T) {
	for _, alias := range []string{"kcp", "mkcp"} {
		t.Run(alias, func(t *testing.T) {
			protocol := conf.TransportProtocol(alias)
			compiled, err := (&conf.StreamConfig{Network: &protocol}).Build()
			if err != nil {
				t.Fatal(err)
			}
			memory, err := internet.ToMemoryStreamConfig(compiled)
			if err != nil {
				t.Fatal(err)
			}
			if memory.ProtocolName != "mkcp" {
				t.Fatalf("Pinned Core canonical KCP transport changed: %s", memory.ProtocolName)
			}
			if err := (&internet.NativeDNSHandler{}).ValidateTransport(memory); !errors.Is(err, internet.ErrNativeDNSUnsupported) {
				t.Fatal("Unqualified canonical mKCP path was accepted")
			}
		})
	}
}
