//go:build !unix

package fscopy

import "os"

// verifyDirNofollow is a no-op on non-unix platforms where O_NOFOLLOW is not
// available. The directory traversal proceeds with the pathname-based approach
// (the same as before this hardening was added). See the unix implementation
// in verify_unix.go for the full doc comment.
func verifyDirNofollow(path string, expectedDev, expectedIno uint64) error {
	return nil
}

// dirIdentity returns zeros on non-unix platforms (the dev+inode check is only
// meaningful on unix where Stat_t exposes these fields).
func dirIdentity(path string, info os.FileInfo) (dev uint64, ino uint64) {
	return 0, 0
}
