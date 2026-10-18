//go:build !windows

package native_dns_context_runtime_test

import (
	"os"
	"testing"
)

func writeLauncherPrivatePolicy(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("private launcher fixture file failed")
	}
}
