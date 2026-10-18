package main

// This opt-in file is trusted parent metadata. Imported Core JSON cannot grant
// it. The expected epoch is a fresh host-session nonce, not a replay registry;
// check and run intentionally reuse the same file/nonce for one candidate.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/nativeinstance"
)

const maxPrivatePolicyBytes = 8 << 10

var errPrivatePolicy = errors.New("native private policy rejected")

type privatePolicy struct {
	bridge *nativeinstance.SystemDNSBridgePolicy
	input  *nativeinstance.ManagedInputPolicy
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func readPrivatePolicy(path string, source []byte, epoch string) (privatePolicy, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxPrivatePolicyBytes {
		return privatePolicy{}, errPrivatePolicy
	}
	file, err := openPrivatePolicy(path)
	if err != nil {
		return privatePolicy{}, errPrivatePolicy
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > maxPrivatePolicyBytes || privatePolicyPermissions(file, info) != nil {
		return privatePolicy{}, errPrivatePolicy
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPrivatePolicyBytes+1))
	if err != nil {
		return privatePolicy{}, errPrivatePolicy
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || privatePolicyPermissions(file, after) != nil {
		return privatePolicy{}, errPrivatePolicy
	}
	return parsePrivatePolicy(data, source, epoch)
}

func parsePrivatePolicy(data, source []byte, epoch string) (privatePolicy, error) {
	fail := func() (privatePolicy, error) { return privatePolicy{}, errPrivatePolicy }
	if len(data) > maxPrivatePolicyBytes || !utf8.Valid(data) || !lowerHex(epoch, 32) {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return fail()
	}
	values := make(map[string]json.RawMessage, 8)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return fail()
		}
		switch name {
		case "schema", "capability", "source_digest", "epoch", "virtual_ipv4", "listen", "username", "password":
		default:
			return fail()
		}
		if _, duplicate := values[name]; duplicate {
			return fail()
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return fail()
		}
		values[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') || len(values) != 8 {
		return fail()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fail()
	}
	var schema int
	if json.Unmarshal(values["schema"], &schema) != nil || schema != launcherSchema {
		return fail()
	}
	stringsByKey := make(map[string]string, 7)
	for key, value := range values {
		if key == "schema" {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || text == "" || strings.ContainsRune(text, '\x00') {
			return fail()
		}
		stringsByKey[key] = text
	}
	digest := sha256.Sum256(source)
	if stringsByKey["capability"] != launcherCapability || !lowerHex(stringsByKey["source_digest"], 64) ||
		stringsByKey["source_digest"] != hex.EncodeToString(digest[:]) || stringsByKey["epoch"] != epoch {
		return fail()
	}
	virtual, err := netip.ParseAddr(stringsByKey["virtual_ipv4"])
	if err != nil || !virtual.Is4() || virtual.IsUnspecified() || virtual.IsMulticast() {
		return fail()
	}
	listen, err := netip.ParseAddrPort(stringsByKey["listen"])
	if err != nil || listen.Addr() != netip.MustParseAddr("127.0.0.1") || listen.Port() == 0 ||
		len(stringsByKey["username"]) > 255 || len(stringsByKey["password"]) > 255 {
		return fail()
	}
	return privatePolicy{
		bridge: &nativeinstance.SystemDNSBridgePolicy{VirtualIPv4: virtual},
		input:  &nativeinstance.ManagedInputPolicy{Listen: listen, Username: stringsByKey["username"], Password: stringsByKey["password"]},
	}, nil
}
