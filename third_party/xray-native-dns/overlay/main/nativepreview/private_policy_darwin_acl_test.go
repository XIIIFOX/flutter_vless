//go:build darwin && cgo

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeLauncherPrivatePolicyDarwinExtendedACLRefused(t *testing.T) {
	source := []byte("{}")
	path := filepath.Join(t.TempDir(), "acl-policy.json")
	createTestPrivatePolicy(t, path, testPrivatePolicy(t, source))
	if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != nil {
		t.Fatal("plain private control rejected")
	}
	// Only this owned synthetic tempfile is modified. No real credential, Core,
	// network, device, or system setting is involved in the filesystem regression.
	if exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run() != nil {
		t.Fatal("fixture ACL addition failed")
	}
	t.Cleanup(func() {
		if exec.Command("/bin/chmod", "-N", path).Run() != nil {
			t.Error("owned fixture ACL cleanup failed")
		}
	})
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("ACL control did not retain misleading0600 mode")
	}
	if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != errPrivatePolicy {
		t.Fatal("extended ACL read grant admitted")
	}
}
