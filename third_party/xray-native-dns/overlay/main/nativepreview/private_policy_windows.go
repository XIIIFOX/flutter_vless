//go:build windows

package main

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privatePolicyFilesQualified = true

func openPrivatePolicy(path string) (*os.File, error) {
	// No UNC/device/network path; only a normal local drive-qualified file.
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) {
		return nil, errPrivatePolicy
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errPrivatePolicy
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errPrivatePolicy
	}
	file := os.NewFile(uintptr(handle), "native-private-policy")
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		file.Close()
		return nil, errPrivatePolicy
	}
	return file, nil
}

func privatePolicyPermissions(file *os.File, _ os.FileInfo) error {
	security, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errPrivatePolicy
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errPrivatePolicy
	}
	return privatePolicyWindowsSecurity(security, user.User.Sid)
}

func privatePolicyWindowsSecurity(security *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if security == nil || user == nil {
		return errPrivatePolicy
	}
	owner, _, err := security.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return errPrivatePolicy
	}
	control, _, err := security.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errPrivatePolicy
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil || acl.AceCount < 1 || acl.AceCount > 2 {
		return errPrivatePolicy
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return errPrivatePolicy
	}
	userAllowed := false
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 {
			return errPrivatePolicy
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) {
			return errPrivatePolicy
		}
		if sid.Equals(user) {
			userAllowed = ace.Mask&(windows.FILE_READ_DATA|windows.GENERIC_READ|windows.GENERIC_ALL) != 0
		} else if !sid.Equals(system) {
			return errPrivatePolicy
		}
	}
	if !userAllowed {
		return errPrivatePolicy
	}
	return nil
}
