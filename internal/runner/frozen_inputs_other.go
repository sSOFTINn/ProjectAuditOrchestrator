//go:build !windows

package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func frozenOpenFlags(directory bool) int {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	return flags
}

func frozenOpenPath(path string, directory bool) (*os.File, error) {
	fd, err := syscall.Open(path, frozenOpenFlags(directory), 0)
	if err != nil {
		return nil, &os.PathError{Op: "open frozen input", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func frozenOpenRelative(parent *os.File, name, path string, directory bool) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, frozenOpenFlags(directory), 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat frozen input", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func frozenHoldPrivate(string, bool) (*os.File, error) { return nil, nil }

func frozenCheckPrivateParent(parent string) error {
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return errors.New("frozen-input parent must be an owner-only directory owned by the current user")
	}
	for path := parent; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) || (info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return errors.New("frozen-input parent has an ancestor mutable by another user")
		}
		if filepath.Dir(path) == path {
			return nil
		}
	}
}

func PinExecutable(ctx context.Context, _, _ string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("native executable pinning cannot exclude Unix writers; use a private frozen executable copy")
}
