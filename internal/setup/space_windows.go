//go:build windows

package setup

import (
	"errors"
	"syscall"
	"unsafe"
)

func availableBytes(path string) (uint64, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	var available, total, free uint64
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	ok, _, callErr := proc.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if ok == 0 {
		return 0, errors.Join(errors.New("cannot read installation volume free space"), callErr)
	}
	return available, nil
}
