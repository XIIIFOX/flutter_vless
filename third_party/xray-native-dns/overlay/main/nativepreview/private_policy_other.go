//go:build !unix && !windows

package main

import "os"

const privatePolicyFilesQualified = false

// An unqualified platform must not infer private permissions from FileMode.
func openPrivatePolicy(string) (*os.File, error)           { return nil, errPrivatePolicy }
func privatePolicyPermissions(*os.File, os.FileInfo) error { return errPrivatePolicy }
