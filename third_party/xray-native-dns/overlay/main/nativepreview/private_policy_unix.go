//go:build unix

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openPrivatePolicy(path string) (*os.File, error) {
	// Nonblocking/no-follow prevents replacement with a FIFO or symlink from
	// turning the bounded private-document read into an unbounded open.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errPrivatePolicy
	}
	return os.NewFile(uintptr(fd), "native-private-policy"), nil
}

func privatePolicyPermissions(file *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errPrivatePolicy
	}
	return privatePolicyExtendedACL(file)
}
