package XRay

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestSetAssetLocation(t *testing.T) {
	directory := t.TempDir()
	for _, name := range requiredGeoAssetFiles {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = SetAssetLocation("")
	})

	if err := SetAssetLocation(directory); err != nil {
		t.Fatalf("SetAssetLocation returned an error: %v", err)
	}
	if got := platform.GetAssetLocation("geoip.dat"); got != filepath.Join(directory, "geoip.dat") {
		t.Fatalf("GetAssetLocation returned %q", got)
	}
	if got := os.Getenv("XRAY_LOCATION_ASSET"); got != directory {
		t.Fatalf("XRAY_LOCATION_ASSET = %q, want %q", got, directory)
	}

	if err := SetAssetLocation(""); err != nil {
		t.Fatalf("clearing asset location returned an error: %v", err)
	}
	if _, found := os.LookupEnv("XRAY_LOCATION_ASSET"); found {
		t.Fatal("XRAY_LOCATION_ASSET was not cleared")
	}
	if _, found := os.LookupEnv(platform.AssetLocation); found {
		t.Fatalf("%s was not cleared", platform.AssetLocation)
	}
}

func TestSetAssetLocationRejectsIncompleteDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "geoip.dat"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := SetAssetLocation(directory)
	if err == nil {
		t.Fatal("SetAssetLocation accepted a directory without geosite.dat")
	}
}

func TestSetAssetLocationRejectsRelativeAndEmptyFiles(t *testing.T) {
	if err := SetAssetLocation("relative/assets"); err == nil {
		t.Fatal("SetAssetLocation accepted a relative path")
	}

	directory := t.TempDir()
	for _, name := range requiredGeoAssetFiles {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetAssetLocation(directory); err == nil {
		t.Fatal("SetAssetLocation accepted empty geo assets")
	}
}
