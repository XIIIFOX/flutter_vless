package XRay

import (
	"bytes"

	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func init() {
	// Decode/build can emit warnings before the first runtime starts. Never
	// expose those raw messages while checking an untrusted candidate document.
	xlog.RegisterHandler(privateLogHandler{})
}

// CheckPrivate performs Core's decode/build stages without creating a runtime,
// opening listeners, replacing coreInstance, or changing process environment.
// Nonempty Env is refused before Build: pinned Core applies every decoded Env
// entry process-wide, including null string values decoded as empty strings.
// This is an interim preflight limitation, not scoped support for the feature;
// the caller document and StartPrivate's existing Env behavior stay unchanged.
// It returns only a closed numeric result; no input, filenames or Core error
// strings cross the native boundary. This is an additive bridge capability.
//
// ABI 1: low byte = stage (0 success, 1 privacy, 2 decode, 3 build,
// 4 internal failure, 5 environment policy); next byte = section (1 inbound, 2 outbound);
// remaining bits = index + 1, or zero when no safe location is available.
func CheckPrivate(config []byte) (result int64) {
	defer func() {
		if recover() != nil {
			result = 4
		}
	}()
	prepared, _, _, err := privateConfig(config)
	if err != nil {
		return 1
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		return 2
	}
	if len(decoded.Env) != 0 {
		return 5
	}
	if _, err = decoded.Build(); err == nil {
		return 0
	}

	// Locate failures only after a failed full build. Re-decode because Build
	// may normalize its input. Successful candidates pay for one Core build.
	decoded, err = serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		return 2
	}
	for index, inbound := range decoded.InboundConfigs {
		if _, err := inbound.Build(); err != nil {
			return 3 | (1 << 8) | (int64(index+1) << 16)
		}
	}
	for index, outbound := range decoded.OutboundConfigs {
		if _, err := outbound.Build(); err != nil {
			return 3 | (2 << 8) | (int64(index+1) << 16)
		}
	}
	return 3
}
