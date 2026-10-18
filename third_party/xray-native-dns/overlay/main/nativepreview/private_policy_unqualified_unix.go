//go:build unix && !darwin && !linux

package main

import "os"

const privatePolicyFilesQualified = false

// Other Unix ACL models have not been qualified for this private-file entry.
func privatePolicyExtendedACL(*os.File) error { return errPrivatePolicy }
