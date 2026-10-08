//go:build windows

package target

import (
	"os"
	"syscall"
)

// isReparsePoint detects Windows junctions and other reparse points before WalkDir can descend
// through them. The target tree treats all of them as metadata, never as content to follow.
func isReparsePoint(path string) bool {
	attributes, err := syscall.GetFileAttributes(syscall.StringToUTF16Ptr(path))
	return err == nil && attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// Open the entry itself instead of following a leaf reparse point introduced
// between the path check and open. The subsequent handle stat admits only the
// confirmed regular file or directory.
func openTargetEntry(path string, directory bool) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(syscall.FILE_ATTRIBUTE_NORMAL | syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open target entry", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
