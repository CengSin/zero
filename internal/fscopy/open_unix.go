//go:build unix

package fscopy

import (
	"os"

	"golang.org/x/sys/unix"
)

// openRegularRead opens a regular file for reading without following a final
// symlink: O_NOFOLLOW makes the open fail (ELOOP) if the path is a symlink,
// so a path that was stat'd as a regular file cannot be swapped for a link
// between the check and the open.
func openRegularRead(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openRegularWrite creates or truncates a regular file for writing without
// following a final symlink: a pre-placed symlink at the destination is refused
// instead of being followed, so the copy cannot be redirected elsewhere.
func openRegularWrite(path string, perm uint32) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
