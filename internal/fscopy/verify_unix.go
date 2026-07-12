//go:build unix

package fscopy

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// verifyDirNofollow opens path with O_NOFOLLOW|O_DIRECTORY and verifies the
// opened fd refers to the same directory that was previously stat'd (same dev
// + inode). This closes the TOCTOU window where an attacker could replace a
// directory with a symlink between os.Lstat and os.ReadDir:
//
//   - O_NOFOLLOW makes the open fail (ELOOP) if the final component is a symlink.
//   - O_DIRECTORY rejects non-directories.
//   - The dev+inode comparison catches a swapped-in symlink to a directory
//     that was created between the check and the open (the open would follow
//     it — O_NOFOLLOW only protects the final component when the open target
//     IS a symlink; if the target was replaced with a different directory,
//     O_NOFOLLOW doesn't help, but the inode check does).
//
// On success the caller should proceed with the recursive operation; on failure
// the directory must be skipped (or the operation aborted).
func verifyDirNofollow(path string, expectedDev, expectedIno uint64) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if uint64(stat.Dev) != expectedDev || uint64(stat.Ino) != expectedIno {
		return &os.PathError{Op: "verify", Path: path, Err: fmt.Errorf("directory replaced during traversal (dev/inode mismatch)")}
	}
	return nil
}

// dirIdentity returns the device and inode numbers for a directory at path,
// which are used by verifyDirNofollow to detect a swapped directory.
func dirIdentity(path string, info os.FileInfo) (dev uint64, ino uint64) {
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		return uint64(stat.Dev), uint64(stat.Ino)
	}
	// Fallback: stat again via the unix package to get the raw dev/ino.
	var s unix.Stat_t
	if err := unix.Stat(path, &s); err != nil {
		return 0, 0
	}
	return uint64(s.Dev), uint64(s.Ino)
}
