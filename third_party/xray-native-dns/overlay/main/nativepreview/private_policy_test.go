package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const testPolicyEpoch = "0123456789abcdef0123456789abcdef"

func testPrivatePolicy(t *testing.T, source []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(source)
	data, err := json.Marshal(map[string]any{"schema": 1, "capability": launcherCapability, "source_digest": hex.EncodeToString(hash[:]), "epoch": testPolicyEpoch,
		"virtual_ipv4": "198.18.0.53", "listen": "127.0.0.1:23457", "username": "private-user-canary", "password": "private-password-canary"})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNativeLauncherPrivatePolicyExactBinding(t *testing.T) {
	source := []byte("{ \"caller\":true }")
	data := testPrivatePolicy(t, source)
	beforeSource, beforeData := append([]byte(nil), source...), append([]byte(nil), data...)
	policy, err := parsePrivatePolicy(data, source, testPolicyEpoch)
	if err != nil || policy.bridge.VirtualIPv4.String() != "198.18.0.53" || policy.input.Listen.String() != "127.0.0.1:23457" || policy.input.Password != "private-password-canary" {
		t.Fatal("private side policy was not bound exactly")
	}
	if !bytes.Equal(source, beforeSource) || !bytes.Equal(data, beforeData) {
		t.Fatal("caller source/private document mutated")
	}
	for name, mutation := range map[string]func(map[string]any){
		"schema": func(m map[string]any) { m["schema"] = 2 }, "capability": func(m map[string]any) { m["capability"] = "legacy" },
		"digest": func(m map[string]any) { m["source_digest"] = strings.Repeat("0", 64) }, "epoch": func(m map[string]any) { m["epoch"] = strings.Repeat("0", 32) },
		"unknown": func(m map[string]any) { m["untrusted"] = true }, "case-alias": func(m map[string]any) { m["Schema"] = 1 },
		"missing": func(m map[string]any) { delete(m, "password") }, "empty-password": func(m map[string]any) { m["password"] = "" },
		"long-password": func(m map[string]any) { m["password"] = strings.Repeat("p", 256) }, "nul": func(m map[string]any) { m["username"] = "u\x00x" },
		"string-schema": func(m map[string]any) { m["schema"] = "1" }, "nested": func(m map[string]any) { m["listen"] = map[string]any{"listen": "127.0.0.1:53"} },
		"numeric-password": func(m map[string]any) { m["password"] = 123 }, "null": func(m map[string]any) { m["password"] = nil },
		"wildcard": func(m map[string]any) { m["listen"] = "0.0.0.0:53" }, "zero-port": func(m map[string]any) { m["listen"] = "127.0.0.1:0" },
		"mapped": func(m map[string]any) { m["virtual_ipv4"] = "::ffff:198.18.0.53" }, "unspecified": func(m map[string]any) { m["virtual_ipv4"] = "0.0.0.0" },
	} {
		t.Run(name, func(t *testing.T) {
			var object map[string]any
			if json.Unmarshal(data, &object) != nil {
				t.Fatal("control decode")
			}
			mutation(object)
			changed, _ := json.Marshal(object)
			if _, err := parsePrivatePolicy(changed, source, testPolicyEpoch); err != errPrivatePolicy {
				t.Fatal("invalid document did not return fixed refusal")
			}
		})
	}
}

func TestNativeLauncherPrivatePolicyRejectsAmbiguousWire(t *testing.T) {
	source := []byte("{}")
	data := testPrivatePolicy(t, source)
	cases := [][]byte{append(append([]byte(nil), data...), []byte("{}")...), bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1), bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1,"\u0073chema":1`), 1), bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1.0`), 1), append(append([]byte(nil), data...), 0xff), []byte("[]"), bytes.Repeat([]byte{' '}, maxPrivatePolicyBytes+1)}
	for i, value := range cases {
		if _, err := parsePrivatePolicy(value, source, testPolicyEpoch); err != errPrivatePolicy {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := parsePrivatePolicy(data, append(source, ' '), testPolicyEpoch); err != errPrivatePolicy {
		t.Fatal("byte-different source admitted")
	}
	if _, err := parsePrivatePolicy(data, source, strings.ToUpper(testPolicyEpoch)); err != errPrivatePolicy {
		t.Fatal("noncanonical epoch admitted")
	}
}

func TestNativeLauncherPrivatePolicyArgumentsAndOutput(t *testing.T) {
	path, _ := filepath.Abs("private-policy-canary.json")
	args := append(testArguments(), "--private-policy", path, "--policy-epoch", testPolicyEpoch)
	before := append([]string(nil), args...)
	options, err := parseOptions(args)
	if err != nil || options.privatePath != path || options.epoch != testPolicyEpoch || !reflect.DeepEqual(args, before) {
		t.Fatal("trusted private-policy arguments changed")
	}
	for _, suffix := range [][]string{{"--private-policy", path}, {"--policy-epoch", testPolicyEpoch}, {"--private-policy", "relative.json", "--policy-epoch", testPolicyEpoch}, {"--private-policy", path, "--policy-epoch", "old"}} {
		if _, err := parseOptions(append(testArguments(), suffix...)); err != errArguments {
			t.Fatal("incomplete private-policy binding accepted")
		}
	}
	var output bytes.Buffer
	if emit(&output, "prepared", "", strings.Repeat("a", 64), testPolicyEpoch) != nil {
		t.Fatal("safe output failed")
	}
	var response map[string]any
	if json.Unmarshal(output.Bytes(), &response) != nil || response["policy_epoch"] != testPolicyEpoch || strings.Contains(output.String(), "private-user") || strings.Contains(output.String(), "private-password") {
		t.Fatal("private policy response leaked or lost binding")
	}
}

func TestNativeLauncherPrivatePolicyFileAdmission(t *testing.T) {
	source := []byte("{}")
	data := testPrivatePolicy(t, source)
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	createTestPrivatePolicy(t, path, data)
	if !privatePolicyFilesQualified {
		if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != errPrivatePolicy {
			t.Fatal("unqualified platform fell back to mode-only private file admission")
		}
		return
	}
	if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != nil {
		t.Fatal("private file rejected", err)
	}
	if _, err := readPrivatePolicy(dir, source, testPolicyEpoch); err != errPrivatePolicy {
		t.Fatal("directory accepted")
	}
	link := filepath.Join(dir, "link.json")
	if os.Symlink(path, link) == nil {
		if _, err := readPrivatePolicy(link, source, testPolicyEpoch); err != errPrivatePolicy {
			t.Fatal("symlink accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if os.Chmod(path, 0644) != nil {
			t.Fatal("control chmod")
		}
		if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != errPrivatePolicy {
			t.Fatal("public permissions accepted")
		}
		if os.Chmod(path, 0600) != nil {
			t.Fatal("control restore")
		}
	}
	if os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxPrivatePolicyBytes+1), 0600) != nil {
		t.Fatal("oversize control write")
	}
	if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != errPrivatePolicy {
		t.Fatal("oversize accepted")
	}
}

func TestNativeLauncherPrivatePolicyFailureIsClosed(t *testing.T) {
	// execute reaches only the file/schema gate. No Core constructor or resolver.
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "caller.json")
	source := []byte("{}")
	if os.WriteFile(sourcePath, source, 0600) != nil {
		t.Fatal("source write")
	}
	path := filepath.Join(dir, "policy.json")
	createTestPrivatePolicy(t, path, []byte(`{"password":"private-password-canary"}`))
	args := testArguments()
	args[2] = sourcePath
	args = append(args, "--private-policy", path, "--policy-epoch", testPolicyEpoch)
	var output bytes.Buffer
	if execute(context.Background(), args, strings.NewReader(""), &output) != 1 {
		t.Fatal("invalid private policy succeeded")
	}
	var result response
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Stage != "private-policy" || result.PolicyEpoch != "" || result.SourceDigest != "" || strings.Contains(output.String(), "canary") {
		t.Fatal("failure exposed policy data")
	}
}
