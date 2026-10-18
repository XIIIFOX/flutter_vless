//go:build windows

package native_dns_context_runtime_test

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func writeLauncherPrivatePolicy(t *testing.T, path string, data []byte) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("private fixture token failed")
	}
	sid := user.User.Sid.String()
	security, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal("private fixture security descriptor failed")
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: security}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("private fixture path failed")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("private fixture protected creation failed")
	}
	file := os.NewFile(uintptr(handle), "private-launcher-fixture")
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		t.Fatal("private fixture write failed")
	}
}
