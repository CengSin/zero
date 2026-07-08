// Package fscopy provides safe directory-tree copy and content-hash utilities.
// It is shared by the plugin installer and the skill installer so security
// properties (skip .git, reject symlinks, skip non-regular files, deterministic
// sort order) are defined once.
package fscopy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// CopyTree recursively copies regular files and directories from src to dst. It
// skips the .git directory (clone metadata) and refuses symlinks so a malicious
// source cannot smuggle a link that escapes the install dir. Copying is pure
// I/O — it never executes anything it copies.
func CopyTree(src string, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == ".git" {
			continue
		}
		srcPath := filepath.Join(src, name)
		dstPath := filepath.Join(dst, name)
		info, err := os.Lstat(srcPath)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			// Never recreate a symlink: it could point outside the install dir and
			// turn a copy into a write/read primitive elsewhere.
			continue
		case info.IsDir():
			if err := CopyTree(srcPath, dstPath); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			// CopyFile re-stats the opened file descriptor itself (not this Lstat
			// result) so there is no TOCTOU window between the check and the read.
			if err := CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		default:
			// Skip FIFOs, sockets, devices.
			continue
		}
	}
	return nil
}

// CopyFile copies a single regular file from src to dst. The source is opened
// and then fstat'd on the already-open descriptor, so the kind and permission
// bits come from the fd actually read — a symlink or other file type swapped in
// after the open cannot be read or mis-classified (no TOCTOU). The destination
// is created or truncated without following a final symlink (O_NOFOLLOW on
// unix), so a pre-placed destination symlink cannot redirect the copy outside
// the install dir. The source's permission bits are applied to the copy so
// executables stay executable. Copying is pure I/O — it never executes anything.
func CopyFile(src string, dst string) error {
	in, err := openRegularRead(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		// The entry was regular when listed but the open resolved something else
		// (e.g. a symlink or special file); refuse rather than copy it.
		return &os.PathError{Op: "copy", Path: src, Err: fmt.Errorf("not a regular file")}
	}
	out, err := openRegularWrite(dst, uint32(info.Mode().Perm()))
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	// openRegularWrite applies perm & ~umask, which can drop requested bits;
	// chmod the open descriptor so the source mode is preserved exactly.
	if err := out.Chmod(info.Mode().Perm()); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// HashTree computes a content hash over the same filtered tree that CopyTree
// installs: regular files only, .git and symlinks skipped, walked in a stable
// sorted order. Each file contributes its relative path, executable bit, size,
// and bytes, so renames, mode flips, size changes, and content edits all change
// the hash, and the stream is self-delimiting (no two trees collide by shifting
// bytes across file boundaries).
func HashTree(root string) (string, error) {
	hasher := sha256.New()
	if err := hashTreeInto(hasher, root, root); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func hashTreeInto(hasher io.Writer, root string, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if name == ".git" {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			// Skipped by CopyTree, so excluded from the hash too.
			continue
		case info.IsDir():
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			// Directory header carries a type tag and explicit size 0 so a
			// directory and a file with the same name cannot collide, and every
			// entry is self-delimiting.
			header := fmt.Sprintf("%s\x00dir\x000\x00", filepath.ToSlash(rel))
			if _, err := io.WriteString(hasher, header); err != nil {
				return err
			}
			if err := hashTreeInto(hasher, root, path); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			executable := 0
			if info.Mode().Perm()&0o111 != 0 {
				executable = 1
			}
			// Null-delimited header tags the type, executable state, and exact
			// byte size; paths cannot contain null bytes, and the size makes each
			// file's content self-delimiting so two trees cannot collide by
			// shifting bytes across file boundaries.
			header := fmt.Sprintf("%s\x00file\x00%d\x00%d\x00", filepath.ToSlash(rel), executable, info.Size())
			if _, err := io.WriteString(hasher, header); err != nil {
				return err
			}
			file, err := openRegularRead(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(hasher, file); err != nil {
				_ = file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		default:
			// FIFOs, sockets, devices: skipped by CopyTree, excluded here.
			continue
		}
	}
	return nil
}
