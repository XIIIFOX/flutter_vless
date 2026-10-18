//go:build darwin && cgo

package main

/*
#include <sys/acl.h>
#include <sys/stat.h>
#include <errno.h>

// Any extended entry (including an apparent deny) is outside this private
// metadata contract. Qualification is based on the open handle, not its path.
static int native_private_policy_acl_empty(int fd) {
	errno = 0;
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		// Darwin represents an absent extended ACL as NULL/ENOENT, including
		// an existing regular file. Do not confuse it with an invalid fd.
		int absent = errno == ENOENT;
		struct stat info;
		return absent && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) ? 0 : -1;
	}
	if (acl_valid(acl) != 0) { acl_free(acl); return -1; }
	acl_entry_t entry;
	errno = 0;
	int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
	// Darwin returns 0 for an entry and -1/EINVAL at the end. Validate the
	// ACL first so EINVAL here can only mean no FIRST_ENTRY in a valid ACL.
	int empty = result == -1 && errno == EINVAL;
	int freed = acl_free(acl);
	return empty && freed == 0 ? 0 : -1;
}
*/
import "C"

import "os"

const privatePolicyFilesQualified = true

func privatePolicyExtendedACL(file *os.File) error {
	if file == nil || C.native_private_policy_acl_empty(C.int(file.Fd())) != 0 {
		return errPrivatePolicy
	}
	return nil
}
