//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func createTestPrivatePolicy(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("private fixture file creation failed")
	}
}

type testPolicyInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (info testPolicyInfo) Sys() any { return info.stat }

func TestNativeLauncherPrivatePolicyUnixOwner(t *testing.T) {
	path := t.TempDir() + "/policy.json"
	createTestPrivatePolicy(t, path, []byte("{}"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("fixture stat failed")
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid++
	if privatePolicyPermissions(nil, testPolicyInfo{info, &stat}) != errPrivatePolicy {
		t.Fatal("foreign owner accepted")
	}
}
