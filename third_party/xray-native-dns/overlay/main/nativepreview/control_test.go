package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLauncherBoundedControl(t *testing.T) {
	for _, value := range []string{"", "stop\n"} {
		if !stopCommand(strings.NewReader(value)) {
			t.Fatal("parent stop rejected")
		}
	}
	for _, value := range []string{"stop", "STOP\n", "stop\r\n", "prepare private-canary\n", strings.Repeat("private-canary", 1024)} {
		if stopCommand(strings.NewReader(value)) {
			t.Fatal("untrusted control accepted")
		}
	}
}

func TestNativeLauncherClosedOutput(t *testing.T) {
	for _, args := range [][]string{{"capabilities"}, {"run", "--private-canary", "sensitive-host.invalid"}} {
		var output bytes.Buffer
		code := execute(context.Background(), args, strings.NewReader(""), &output)
		var result response
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal("single structured response required", err)
		}
		if result.HostQualified || result.Schema != launcherSchema || result.Capability != launcherCapability || result.CoreCommit != coreCommit {
			t.Fatal("wrong closed capability")
		}
		if strings.Contains(output.String(), "private-canary") || strings.Contains(output.String(), "sensitive-host") {
			t.Fatal("argument data exposed")
		}
		if (code == 0) != (args[0] == "capabilities") {
			t.Fatal("wrong status")
		}
	}
}

func TestNativeLauncherDocumentBound(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "private.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := document(path); err != nil || string(result) != "{}" {
		t.Fatal("regular source read")
	}
	if _, err := document(directory); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxDocumentBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := document(path); err == nil {
		t.Fatal("unbounded source accepted")
	}
}
