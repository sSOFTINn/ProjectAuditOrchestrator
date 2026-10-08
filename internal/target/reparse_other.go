//go:build !windows

package target

import (
	"os"
	"syscall"
)

func isReparsePoint(string) bool { return false }

func openTargetEntry(path string, directory bool) (*os.File, error) {
	// NONBLOCK prevents a leaf replacement with a FIFO from blocking before
	// handle metadata can reject it. It has no effect on regular-file reads.
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open target entry", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
