package native_dns_preservation_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

// File-only acceptance shared with the platform runtime fixtures. The native
// exporters prepare JSON, not a plugin session; argument propagation is tested
// separately by the Android, Apple and Windows runtime fixtures.
func testAssetFiles(t *testing.T, native bool) {
	t.Run("custom_asset_root", func(t *testing.T) {
		_, source, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("asset fixture source path unavailable")
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "tool", "fixtures", "compatibility", "asset-files.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			File, Code, Domain, Base64, SHA256 string
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		content, err := base64.StdEncoding.DecodeString(fixture.Base64)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		if fixture.File != "caller-geosite.dat" || hex.EncodeToString(digest[:]) != fixture.SHA256 {
			t.Fatal("canonical asset name or digest mismatch")
		}
		var sites geodata.GeoSiteList
		if err := proto.Unmarshal(content, &sites); err != nil || len(sites.Entry) != 1 ||
			sites.Entry[0].Code != fixture.Code || len(sites.Entry[0].Domain) != 1 ||
			sites.Entry[0].Domain[0].Type != geodata.Domain_Full || sites.Entry[0].Domain[0].Value != fixture.Domain {
			t.Fatal("canonical asset must contain the one expected full domain", err)
		}
		root, missing := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(root, fixture.File), content, 0o600); err != nil {
			t.Fatal(err)
		}
		input := map[string]any{
			"dns": map[string]any{"queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}},
			"outbounds": []any{
				map[string]any{"tag": "proxy", "protocol": "http", "settings": map[string]any{"address": "endpoint.invalid", "port": 443}},
				map[string]any{"tag": "direct", "protocol": "freedom"},
			},
			"routing": map[string]any{"rules": []any{map[string]any{
				"type": "field", "domain": []string{"ext:" + fixture.File + ":" + fixture.Code}, "outboundTag": "direct",
			}}},
		}
		document, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if native {
			document, _ = prepare(t, input)
			if !bytes.Contains(document, []byte("ext:"+fixture.File+":"+fixture.Code)) {
				t.Fatal("native preparation discarded the external asset rule")
			}
		}
		build := func() error {
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(document))
			if err != nil {
				return err
			}
			_, err = decoded.Build() // No core.Instance, listener or resolver.
			return err
		}
		for _, key := range []string{"xray.location.asset", "XRAY_LOCATION_ASSET"} {
			t.Setenv(key, missing)
		}
		if err := build(); err == nil {
			t.Fatal("Core accepted a referenced custom file absent from the selected root")
		}
		for _, key := range []string{"xray.location.asset", "XRAY_LOCATION_ASSET"} {
			t.Setenv(key, root)
		}
		if err := build(); err != nil {
			t.Fatal("Core rejected the custom-only root", err)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 || entries[0].Name() != fixture.File {
			t.Fatal("custom root acquired unrelated bundled files", err)
		}
	})
}
