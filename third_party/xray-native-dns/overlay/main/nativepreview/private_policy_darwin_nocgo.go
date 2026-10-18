//go:build darwin && !cgo

package main

import "os"

const privatePolicyFilesQualified = false

// Mode0600 alone does not qualify Darwin extended ACLs. No cgo means this opt-in
// private-file capability is unavailable, not a silent permissions fallback.
func privatePolicyExtendedACL(*os.File) error { return errPrivatePolicy }
