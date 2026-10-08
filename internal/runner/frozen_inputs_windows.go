//go:build windows

package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"syscall"
)

func frozenOpenPath(path string, directory bool) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(syscall.FILE_ATTRIBUTE_NORMAL | syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	// Do not share write or delete access. Already-open writers also cause this
	// open to fail, so pinning cannot admit an active mutation handle.
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "pin frozen input", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	info, err := file.Stat()
	attributes, attributeErr := syscall.GetFileAttributes(name)
	if err != nil || attributeErr != nil || attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		_ = file.Close()
		return nil, errors.New("frozen input must be an unredirected regular file or directory")
	}
	return file, nil
}

func frozenOpenRelative(_ *os.File, _ string, path string, directory bool) (*os.File, error) {
	// Parent handles are held without delete sharing, preventing ancestor swaps.
	return frozenOpenPath(path, directory)
}

func frozenHoldPrivate(path string, directory bool) (*os.File, error) {
	return frozenOpenPath(path, directory)
}

func frozenCheckPrivateParent(string) error {
	// The configured workflow proves its existing parent DACL. Every new base
	// is created with a protected private DACL and retained with a deny-delete
	// handle before any input bytes are written.
	return nil
}

// PinExecutable retains the executable and every ancestor with deny-write and
// deny-delete handles until cleanup. This preserves the native adjacent-file
// layout; DLL/plugin dependencies still require separate platform acceptance.
func PinExecutable(ctx context.Context, path, digest string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sha256Reference.MatchString(digest) {
		return nil, errors.New("native executable pin requires approved SHA-256")
	}
	file, closeAll, err := frozenOpenChain(path, false)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() > FrozenMaxFileBytes {
		closeAll()
		return nil, errors.New("native executable exceeds pinning byte limit")
	}
	session := frozenSession{limits: DefaultFrozenInputLimits()}
	hash := sha256.New()
	if err := session.copyExactly(ctx, hash, file, info.Size(), false); err != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		closeAll()
		return nil, errors.Join(err, errors.New("native executable pin digest mismatch"))
	}
	return func() error { closeAll(); return nil }, nil
}
