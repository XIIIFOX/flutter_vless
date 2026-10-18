//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testPrivatePolicySDDL(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("fixture token unavailable")
	}
	sid := user.User.Sid.String()
	return "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)"
}

func createTestPrivatePolicy(t *testing.T, path string, data []byte) {
	t.Helper()
	createTestPolicyWithDACL(t, path, data, testPrivatePolicySDDL(t))
}

func createTestPolicyWithDACL(t *testing.T, path string, data []byte, sddl string) {
	t.Helper()
	security, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("fixture private security descriptor failed")
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: security}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("fixture path failed")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("fixture protected file failed")
	}
	file := os.NewFile(uintptr(handle), "private-policy-fixture")
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		t.Fatal("fixture private write failed")
	}
}

func TestNativeLauncherPrivatePolicyWindowsACLRefusesBroadOrUnprotected(t *testing.T) {
	source := []byte("{}")
	data := testPrivatePolicy(t, source)
	strict := testPrivatePolicySDDL(t)
	for name, sddl := range map[string]string{
		"public":      strict + "(A;;FR;;;WD)",
		"inherited":   strict + "(A;ID;FR;;;WD)",
		"unprotected": "O:" + windowsCurrentSID(t) + "D:(A;;FA;;;" + windowsCurrentSID(t) + ")",
		"null":        "O:" + windowsCurrentSID(t) + "D:NO_ACCESS_CONTROL",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			createTestPolicyWithDACL(t, path, data, sddl)
			if _, err := readPrivatePolicy(path, source, testPolicyEpoch); err != errPrivatePolicy {
				t.Fatal("unsafe Windows DACL admitted")
			}
		})
	}
}

func windowsCurrentSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("fixture token unavailable")
	}
	return user.User.Sid.String()
}

func TestNativeLauncherPrivatePolicyWindowsDescriptorExactOwner(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("fixture token unavailable")
	}
	sid := current.User.Sid.String()
	for name, sddl := range map[string]string{
		"owner-system": "O:SYD:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)",
		"no-user":      "O:" + sid + "D:P(A;;FA;;;SY)",
		"empty":        "O:" + sid + "D:P",
		"denied":       "O:" + sid + "D:P(D;;FW;;;" + sid + ")(A;;FR;;;" + sid + ")",
	} {
		t.Run(name, func(t *testing.T) {
			security, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal("fixture descriptor invalid")
			}
			if privatePolicyWindowsSecurity(security, current.User.Sid) != errPrivatePolicy {
				t.Fatal("unsafe descriptor admitted")
			}
		})
	}
	security, err := windows.SecurityDescriptorFromString(testPrivatePolicySDDL(t))
	if err != nil || privatePolicyWindowsSecurity(security, current.User.Sid) != nil {
		t.Fatal("exact private descriptor refused")
	}
}
