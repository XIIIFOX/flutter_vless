package XRay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/infra/conf/serial"

	"google.golang.org/protobuf/proto"
)

func assetEnvironment(t *testing.T) {
	t.Helper()
	// Restore every value after the test, including inherited exact/alias keys.
	t.Setenv(platform.AssetLocation, "")
	t.Setenv(platform.NormalizeEnvName(platform.AssetLocation), "")
}

func assetConfigBuild(document string) error {
	decoded, err := serial.DecodeJSONConfig(bytes.NewBufferString(document))
	if err != nil {
		return err
	}
	_, err = decoded.Build() // Decode/Build only: no Core instance or listeners.
	return err
}

func TestSetAssetLocation(t *testing.T) {
	assetEnvironment(t)
	directory := t.TempDir()
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certExact, certAlias := t.TempDir(), t.TempDir()
	t.Setenv(platform.CertLocation, certExact)
	t.Setenv(platform.NormalizeEnvName(platform.CertLocation), certAlias)

	if err := SetAssetLocation(directory); err != nil {
		t.Fatalf("SetAssetLocation returned an error: %v", err)
	}
	if got := platform.GetAssetLocation("geoip.dat"); got != filepath.Join(directory, "geoip.dat") {
		t.Fatalf("GetAssetLocation returned %q", got)
	}
	for _, name := range []string{platform.AssetLocation, platform.NormalizeEnvName(platform.AssetLocation)} {
		if got := os.Getenv(name); got != directory {
			t.Fatalf("%s = %q, want %q", name, got, directory)
		}
	}
	if got := platform.GetCertLocation("caller.pem"); got != filepath.Join(certExact, "caller.pem") {
		t.Fatalf("selecting data assets changed independent certificate lookup: %q", got)
	}

	if err := SetAssetLocation(""); err != nil {
		t.Fatalf("clearing asset location returned an error: %v", err)
	}
	for _, name := range []string{platform.AssetLocation, platform.NormalizeEnvName(platform.AssetLocation)} {
		if _, found := os.LookupEnv(name); found {
			t.Fatalf("%s was not cleared", name)
		}
	}
	if os.Getenv(platform.CertLocation) != certExact || os.Getenv(platform.NormalizeEnvName(platform.CertLocation)) != certAlias {
		t.Fatal("clearing data assets changed independent certificate environment")
	}
	if got := platform.GetCertLocation("caller.pem"); got != filepath.Join(certExact, "caller.pem") {
		t.Fatalf("clearing data assets changed independent certificate lookup: %q", got)
	}
}

func TestSetAssetLocationCustomOnlyAssetsBuildThroughCore(t *testing.T) {
	assetEnvironment(t)
	directory := t.TempDir()
	data, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		Code: "CALLER", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: "caller.test.invalid"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "caller-geosite.dat"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, unused := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(directory, unused)); !os.IsNotExist(err) {
			t.Fatalf("fixture unexpectedly contains standard asset %s", unused)
		}
	}
	if err := SetAssetLocation(directory); err != nil {
		t.Fatalf("custom-only asset root must be accepted: %v", err)
	}
	document := `{"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","domain":["ext:caller-geosite.dat:CALLER"],"outboundTag":"direct"}]}}`
	before := coreInstance
	if err := assetConfigBuild(document); err != nil {
		t.Fatalf("Core rejected the referenced custom GeoSiteList: %v", err)
	}
	// Changing only the selected root makes this same reference unavailable.
	// Core must validate the document instead of accepting a cached old asset.
	if err := SetAssetLocation(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := assetConfigBuild(document); err == nil {
		t.Fatal("Core accepted a missing explicitly referenced custom asset")
	}
	if coreInstance != before {
		t.Fatal("file-only configuration build replaced the runtime")
	}
}

func TestSetAssetLocationEmptyDirectoryForAssetFreeConfiguration(t *testing.T) {
	assetEnvironment(t)
	if err := SetAssetLocation(t.TempDir()); err != nil {
		t.Fatalf("an asset-free config must permit an empty data root: %v", err)
	}
	if err := assetConfigBuild(`{"outbounds":[{"protocol":"freedom"}]}`); err != nil {
		t.Fatalf("asset-free Core config failed: %v", err)
	}
}

func TestSetAssetLocationDefersReferencedFileValidationToCore(t *testing.T) {
	assetEnvironment(t)
	document := `{"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","domain":["ext:caller-geosite.dat:CALLER"],"outboundTag":"direct"}]}}`
	for _, content := range [][]byte{nil, []byte("not a GeoSiteList")} {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "caller-geosite.dat"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := SetAssetLocation(directory); err != nil {
			t.Fatalf("directory selection must not parse unreferenced file contents: %v", err)
		}
		if err := assetConfigBuild(document); err == nil {
			t.Fatal("Core accepted an invalid referenced GeoSiteList")
		}
	}
}

func TestSetAssetLocationRejectsInvalidDirectoryWithoutChangingSelection(t *testing.T) {
	assetEnvironment(t)
	selected := t.TempDir()
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(selected, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetAssetLocation(selected); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"relative/assets", filepath.Join(t.TempDir(), "missing"), file} {
		if err := SetAssetLocation(invalid); err == nil {
			t.Fatalf("accepted invalid asset root %q", invalid)
		}
		for _, name := range []string{platform.AssetLocation, platform.NormalizeEnvName(platform.AssetLocation)} {
			if got := os.Getenv(name); got != selected {
				t.Fatalf("failed selection changed %s to %q", name, got)
			}
		}
	}
}
