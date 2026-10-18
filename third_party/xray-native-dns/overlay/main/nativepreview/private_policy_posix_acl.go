//go:build linux

package main

import "os"

const privatePolicyFilesQualified = true

// Linux/Android POSIX named ACL entries are bounded by the group mask, which is
// encoded in mode bits. Exact0600 therefore denies named/group/other readers.
// Darwin extended ACLs have separate semantics and are checked separately.
func privatePolicyExtendedACL(*os.File) error { return nil }
