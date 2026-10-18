package nativeinstance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	xlog "github.com/xtls/xray-core/common/log"
	jsonreader "github.com/xtls/xray-core/infra/conf/json"
)

// The preview executable is an isolated process: the Core logging registry is
// process-global. No decoder/build/runtime text is exported by this package.
type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}
func silenceLogs()                     { xlog.RegisterHandler(discardLog{}) }

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

func privateDocument(source []byte) ([]byte, error) {
	decoder := json.NewDecoder(&jsonreader.Reader{Reader: bytes.NewReader(source)})
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil || object == nil {
		return nil, ErrDocument
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrDocument
	}
	// Reject ambiguous owned fields before encoding/json's case-insensitive decode.
	for _, name := range []string{"env", "transport", "log", "routing", "dns", "inbounds", "outbounds", "policy", "api", "metrics", "stats", "reverse", "fakeDns", "observatory", "burstObservatory", "version", "geodata"} {
		if _, _, err := owned(object, name); err != nil {
			return nil, ErrDocument
		}
	}
	if value, exists := object["log"]; exists && value != nil {
		log, ok := value.(map[string]any)
		if !ok {
			return nil, ErrDocument
		}
		for _, name := range []string{"access", "error", "loglevel", "dnsLog"} {
			if _, _, err := owned(log, name); err != nil {
				return nil, ErrDocument
			}
		}
	}
	object["log"] = map[string]any{"access": "none", "error": "none", "loglevel": "none", "dnsLog": false}
	for _, name := range []string{"inbounds", "outbounds"} {
		value := object[name]
		if value == nil {
			continue
		}
		entries, ok := value.([]any)
		if !ok {
			return nil, ErrDocument
		}
		for _, value := range entries {
			entry, ok := value.(map[string]any)
			if !ok {
				return nil, ErrDocument
			}
			for _, key := range []string{"protocol", "streamSettings", "settings", "listen", "port", "tag", "sniffing", "sendThrough", "proxySettings", "mux", "targetStrategy"} {
				if _, _, err := owned(entry, key); err != nil {
					return nil, ErrDocument
				}
			}
			stream, exists := entry["streamSettings"]
			if !exists || stream == nil {
				continue
			}
			settings, ok := stream.(map[string]any)
			if !ok {
				return nil, ErrDocument
			}
			if privateStream(settings) != nil {
				return nil, ErrDocument
			}
		}
	}
	result, err := json.Marshal(object)
	if err != nil {
		return nil, ErrDocument
	}
	return result, nil
}
