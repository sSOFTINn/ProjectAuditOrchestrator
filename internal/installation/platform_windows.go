//go:build windows

package installation

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var advapi = syscall.NewLazyDLL("advapi32.dll")
var lockFile = kernel.NewProc("LockFileEx")
var unlockFile = kernel.NewProc("UnlockFileEx")
var moveFile = kernel.NewProc("MoveFileExW")
var namedSecurity = advapi.NewProc("GetNamedSecurityInfoW")
var getAce = advapi.NewProc("GetAce")

type aclHeader struct {
	Revision, Reserved     byte
	Size, Count, Reserved2 uint16
}
type aceHeader struct {
	Type, Flags byte
	Size        uint16
	Mask        uint32
}

// Inspect native ownership and ACLs without launching PowerShell. Unknown allow
// ACE forms are rejected; only the current user, SYSTEM and Administrators may
// own the object or receive access through its DACL.
func ValidatePrivatePath(path string, directory bool) error {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if (directory && !i.IsDir()) || (!directory && !i.Mode().IsRegular()) {
		return errors.New("installation object has an unexpected type")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	self, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var owner *syscall.SID
	var dacl *aclHeader
	var descriptor unsafe.Pointer
	// OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION. A foreign owner
	// can regain control through WRITE_DAC even when the current DACL is narrow.
	status, _, _ := namedSecurity.Call(uintptr(unsafe.Pointer(p)), 1, 1|4, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 {
		return syscall.Errno(status)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	return validatePrivateSecurity(owner, dacl, self)
}

func validatePrivateSecurity(owner *syscall.SID, dacl *aclHeader, self string) error {
	if owner == nil {
		return errors.New("installation object has no owner")
	}
	ownerSID, err := owner.String()
	if err != nil {
		return err
	}
	if ownerSID != self && ownerSID != "S-1-5-18" && ownerSID != "S-1-5-32-544" {
		return errors.New("installation object owner is not the current user, SYSTEM or Administrators")
	}
	if dacl == nil {
		return errors.New("installation object has an unrestricted DACL")
	}
	h := dacl
	if h.Count == 0 || h.Count > 1024 {
		return errors.New("installation DACL is empty or oversized")
	}
	for n := uint32(0); n < uint32(h.Count); n++ {
		var ace unsafe.Pointer
		ok, _, callErr := getAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(n), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 {
			return callErr
		}
		a := (*aceHeader)(ace)
		if a.Type == 1 {
			continue
		} // ACCESS_DENIED_ACE cannot grant access.
		if a.Type != 0 || a.Size < 12 {
			return errors.New("installation DACL contains an unsupported permission entry")
		}
		sid := (*syscall.SID)(unsafe.Add(ace, 8))
		name, err := sid.String()
		if err != nil {
			return err
		}
		if a.Mask != 0 && name != self && name != "S-1-5-18" && name != "S-1-5-32-544" {
			return errors.New("installation object grants access outside its owner, SYSTEM and Administrators")
		}
	}
	return nil
}

func tryLock(f *os.File, exclusive bool) (bool, error) {
	flags := uintptr(1)
	if exclusive {
		flags |= 2
	}
	var o syscall.Overlapped
	ok, _, err := lockFile.Call(f.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if ok != 0 {
		return true, nil
	}
	if errors.Is(err, syscall.Errno(33)) {
		return false, nil
	}
	return false, err
}
func unlock(f *os.File) error {
	var o syscall.Overlapped
	ok, _, err := unlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if ok == 0 {
		return err
	}
	return nil
}
func replaceFile(from, to string) error {
	a, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	b, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	ok, _, err := moveFile.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), 1|8)
	if ok == 0 {
		return err
	}
	return nil
}

// Files are flushed before publication; MoveFileEx WRITE_THROUGH flushes the
// replacement. Windows does not provide Unix directory fsync through os.File.
func syncDirectory(string) error { return nil }
