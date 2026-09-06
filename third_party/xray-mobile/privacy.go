package XRay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	xlog "github.com/xtls/xray-core/common/log"
)

// The mobile runtime never exports arbitrary runtime text. These messages are
// a closed vocabulary shared with Swift diagnostics; the original error remains
// deliberately absent from callbacks, returned errors and stdout.
type privateLogHandler struct {
	logger  Logger
	level   xlog.Severity
	enabled bool
	phase   string
}

func (h privateLogHandler) Handle(message xlog.Message) {
	general, ok := message.(*xlog.GeneralMessage)
	if !ok || !h.enabled || h.logger == nil || general.Severity > h.level {
		return
	}
	if general.Severity <= xlog.Severity_Error {
		h.logger.LogInput("Xray " + h.phase + " error")
	} else {
		h.logger.LogInput("Xray " + h.phase + " warning")
	}
}

func startupFailure(logger Logger, stage string) error {
	message := "Xray startup failed: " + stage
	if logger != nil {
		logger.LogInput(message)
	}
	return errors.New(message)
}

// owned canonicalizes only schema fields controlled by this policy. Header,
// credential and arbitrary user maps retain their original keys and values.
func owned(object map[string]any, name string) (any, bool, error) {
	var key string
	found := false
	for candidate := range object {
		if strings.EqualFold(candidate, name) {
			if found {
				return nil, false, errors.New("ambiguous privacy field")
			}
			key, found = candidate, true
		}
	}
	if !found {
		return nil, false, nil
	}
	value := object[key]
	delete(object, key)
	object[name] = value
	return value, true, nil
}

func privateFinalMask(stream map[string]any) error {
	value, exists, err := owned(stream, "finalmask")
	if err != nil || !exists || value == nil {
		return err
	}
	mask, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid finalmask")
	}
	params, exists, err := owned(mask, "quicParams")
	if err != nil {
		return err
	}
	if exists && params != nil {
		object, ok := params.(map[string]any)
		if !ok {
			return errors.New("invalid QUIC parameters")
		}
		if _, _, err := owned(object, "debug"); err != nil {
			return err
		}
		object["debug"] = false
	}
	for _, network := range []string{"tcp", "udp"} {
		value, exists, err := owned(mask, network)
		if err != nil {
			return err
		}
		if !exists || value == nil {
			continue
		}
		entries, ok := value.([]any)
		if !ok {
			return errors.New("invalid mask entries")
		}
		for _, value := range entries {
			entry, ok := value.(map[string]any)
			if !ok {
				return errors.New("invalid mask entry")
			}
			kind, _, err := owned(entry, "type")
			if err != nil {
				return err
			}
			name, _ := kind.(string)
			if !strings.EqualFold(name, "realm") {
				continue
			}
			settings, exists, err := owned(entry, "settings")
			if err != nil {
				return err
			}
			if !exists || settings == nil {
				continue
			}
			object, ok := settings.(map[string]any)
			if !ok {
				return errors.New("invalid realm settings")
			}
			value, exists, err := owned(object, "tlsConfig")
			if err != nil {
				return err
			}
			if !exists || value == nil {
				continue
			}
			tls, ok := value.(map[string]any)
			if !ok {
				return errors.New("invalid realm TLS settings")
			}
			if _, _, err := owned(tls, "masterKeyLog"); err != nil {
				return err
			}
			tls["masterKeyLog"] = ""
		}
	}
	return nil
}

func privateStream(stream map[string]any) error {
	if err := privateFinalMask(stream); err != nil {
		return err
	}
	for _, name := range []string{"tlsSettings", "realitySettings"} {
		value, exists, err := owned(stream, name)
		if err != nil {
			return err
		}
		if !exists || value == nil {
			continue
		}
		settings, ok := value.(map[string]any)
		if !ok {
			return errors.New("invalid security settings")
		}
		if _, _, err = owned(settings, "masterKeyLog"); err != nil {
			return err
		}
		settings["masterKeyLog"] = ""
		if name == "realitySettings" {
			if _, _, err = owned(settings, "show"); err != nil {
				return err
			}
			settings["show"] = false
		}
	}
	for _, name := range []string{"xhttpSettings", "splithttpSettings"} {
		value, exists, err := owned(stream, name)
		if err != nil {
			return err
		}
		if !exists || value == nil {
			continue
		}
		settings, ok := value.(map[string]any)
		if !ok {
			return errors.New("invalid HTTP transport settings")
		}
		if err = privateDownloads(settings); err != nil {
			return err
		}
		extra, exists, err := owned(settings, "extra")
		if err != nil {
			return err
		}
		if exists && extra != nil {
			object, ok := extra.(map[string]any)
			if !ok {
				return errors.New("invalid HTTP extra settings")
			}
			if err = privateDownloads(object); err != nil {
				return err
			}
		}
	}
	return nil
}

func privateDownloads(settings map[string]any) error {
	value, exists, err := owned(settings, "downloadSettings")
	if err != nil || !exists || value == nil {
		return err
	}
	stream, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid download settings")
	}
	return privateStream(stream)
}

func privateConfig(data []byte) ([]byte, xlog.Severity, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, 0, false, err
	}
	if object == nil {
		return nil, 0, false, errors.New("config must be an object")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, 0, false, errors.New("trailing config data")
	}
	value, exists, err := owned(object, "log")
	if err != nil {
		return nil, 0, false, err
	}
	log := map[string]any{}
	if exists && value != nil {
		var ok bool
		log, ok = value.(map[string]any)
		if !ok {
			return nil, 0, false, errors.New("invalid log settings")
		}
	}
	for _, name := range []string{"access", "error", "loglevel", "dnsLog"} {
		if _, _, err = owned(log, name); err != nil {
			return nil, 0, false, err
		}
	}
	level, _ := log["loglevel"].(string)
	level = strings.ToLower(level)
	if level != "error" && level != "none" {
		level = "warning"
	}
	errorOutput, _ := log["error"].(string)
	enabled := level != "none" && errorOutput != "none"
	severity := xlog.Severity_Warning
	if level == "error" {
		severity = xlog.Severity_Error
	}
	object["log"] = map[string]any{"access": "none", "error": "none", "loglevel": level, "dnsLog": false}
	for _, name := range []string{"inbounds", "outbounds"} {
		value, exists, err = owned(object, name)
		if err != nil {
			return nil, 0, false, err
		}
		if !exists || value == nil {
			continue
		}
		entries, ok := value.([]any)
		if !ok {
			return nil, 0, false, errors.New("invalid proxy entries")
		}
		for _, entry := range entries {
			proxy, ok := entry.(map[string]any)
			if !ok {
				return nil, 0, false, errors.New("invalid proxy entry")
			}
			stream, exists, err := owned(proxy, "streamSettings")
			if err != nil {
				return nil, 0, false, err
			}
			if !exists || stream == nil {
				continue
			}
			settings, ok := stream.(map[string]any)
			if !ok {
				return nil, 0, false, errors.New("invalid stream settings")
			}
			if err = privateStream(settings); err != nil {
				return nil, 0, false, err
			}
		}
	}
	prepared, err := json.Marshal(object)
	return prepared, severity, enabled, err
}
