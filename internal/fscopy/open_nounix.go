//go:build !unix

package fscopy

import "os"

// openRegularRead opens a file for reading. On non-unix platforms O_NOFOLLOW is
// unavailable, so we reject a final-component symlink explicitly with Lstat
// before opening: os.Open would otherwise follow it, which CopyTree already
// skips by type and which HashTree never reads. The caller (CopyFile) also
// fstats the opened descriptor and refuses anything that is not a regular file,
// so a link swapped in after this check still cannot be read.
func openRegularRead(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrInvalid}
	}
	return os.Open(path)
}

// openRegularWrite creates or truncates a file for writing. On non-unix
// platforms O_NOFOLLOW is unavailable, so we refuse a pre-placed symlink at the
// destination with Lstat before opening; os.OpenFile would otherwise follow it
// and redirect the copy elsewhere.
func openRegularWrite(path string, perm uint32) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrInvalid}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(perm))
}
