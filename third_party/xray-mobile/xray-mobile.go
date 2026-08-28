package XRay

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
)

type Logger interface {
	LogInput(s string)
}

var coreInstance *core.Instance

var requiredGeoAssetFiles = []string{"geoip.dat", "geosite.dat"}

// SetAssetLocation configures the directory used by Xray-core to load runtime
// assets such as geoip.dat and geosite.dat.
//
// This function deliberately updates the environment from Go. On iOS, calling
// setenv from Swift after the Go runtime has initialized does not update the
// environment observed by Go's os.LookupEnv. Passing an empty path restores
// Xray's default executable-directory lookup.
func SetAssetLocation(directory string) error {
	assetLocation := platform.NormalizeEnvName(platform.AssetLocation)
	if directory == "" {
		if err := os.Unsetenv(platform.AssetLocation); err != nil {
			return fmt.Errorf("clear %s: %w", platform.AssetLocation, err)
		}
		if err := os.Unsetenv(assetLocation); err != nil {
			return fmt.Errorf("clear %s: %w", assetLocation, err)
		}
		return nil
	}

	if !filepath.IsAbs(directory) {
		return fmt.Errorf("Xray asset directory must be an absolute path: %q", directory)
	}
	directory = filepath.Clean(directory)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("open Xray asset directory %q: %w", directory, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("Xray asset path is not a directory: %q", directory)
	}

	for _, name := range requiredGeoAssetFiles {
		path := filepath.Join(directory, name)
		fileInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("open required Xray asset %q: %w", name, err)
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("required Xray asset is not a regular file: %q", name)
		}
		if fileInfo.Size() == 0 {
			return fmt.Errorf("required Xray asset is empty: %q", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("required Xray asset is not readable %q: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close required Xray asset %q: %w", name, err)
		}
	}

	// Xray accepts both the dotted internal name and XRAY_LOCATION_ASSET.
	// Setting both prevents an inherited value from taking precedence.
	if err := os.Setenv(assetLocation, directory); err != nil {
		return fmt.Errorf("set %s: %w", assetLocation, err)
	}
	if err := os.Setenv(platform.AssetLocation, directory); err != nil {
		_ = os.Unsetenv(assetLocation)
		return fmt.Errorf("set %s: %w", platform.AssetLocation, err)
	}
	return nil
}

func SetMemoryLimit() {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(30 * 1024 * 1024)
}

func Start(config []byte, logger Logger) error {
	conf, err := serial.DecodeJSONConfig(bytes.NewReader(config))
	if err != nil {
		logger.LogInput("Config load error: " + err.Error())
		return err
	}
	pbConfig, err := conf.Build()
	if err != nil {
		return err
	}
	instance, err := core.New(pbConfig)
	if err != nil {
		logger.LogInput("Create XRay error: " + err.Error())
		return err
	}
	err = instance.Start()
	if err != nil {
		logger.LogInput("Start XRay error: " + err.Error())
		return err
	}
	coreInstance = instance
	return nil
}

func Stop() {
	if coreInstance != nil {
		coreInstance.Close()
		coreInstance = nil
	}
}

func GetVersion() string {
	return core.Version()
}

func MeasureDelay(url string) (int64, error) {
	return 0, nil
}

func MeasureOutboundDelay(ConfigureFileContent string, url string) (int64, error) {
	return 0, nil
}

// QueryStats returns all traffic counters as "name>>>value\n" lines.
// Uses VisitCounters which is available in xray-core features/stats.Manager.
// Caller parses "uplink" and "downlink" from counter names.
func QueryStats(tag string) string {
	if coreInstance == nil {
		return ""
	}
	sm := coreInstance.GetFeature(stats.ManagerType())
	if sm == nil {
		return ""
	}
	manager, ok := sm.(stats.Manager)
	if !ok {
		return ""
	}

	var sb strings.Builder
	manager.VisitCounters(func(name string, counter stats.Counter) bool {
		if tag == "" || strings.Contains(name, tag) {
			sb.WriteString(name)
			sb.WriteString(">>>")
			sb.WriteString(itoa(counter.Value()))
			sb.WriteByte('\n')
		}
		return true // continue iteration
	})
	return sb.String()
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	buf := make([]byte, 20)
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte(n%10) + '0'
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
