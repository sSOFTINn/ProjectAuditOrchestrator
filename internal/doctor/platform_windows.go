//go:build windows

package doctor

import (
	"errors"
	"syscall"
	"unsafe"
)

func supportedHost() error {
	var version struct {
		Size, Major, Minor, Build, Platform           uint32
		ServicePack                                   [128]uint16
		ServicePackMajor, ServicePackMinor, SuiteMask uint16
		ProductType, Reserved                         uint8
	}
	version.Size = uint32(unsafe.Sizeof(version))
	status, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&version)))
	if status != 0 || version.Major != 10 || version.Build < 22000 || version.ProductType != 1 {
		return errors.New("Windows 11 workstation is required")
	}
	return nil
}
