//go:build windows

package auditconfig

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var getDriveType = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW")
var convertSDDL = syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

func localPath(path string) bool {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return false
	}
	root, err := syscall.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return false
	}
	typeID, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(root)))
	if typeID != 3 {
		return false
	} // DRIVE_FIXED; excludes mapped network paths.
	for _, part := range strings.Split(path[len(volume):], `\`) {
		if strings.Contains(part, ":") || strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
			return false
		}
		name := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || (len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && name[3] >= '0' && name[3] <= '9') {
			return false
		}
	}
	return true
}

// MakePrivateDirectory creates a new directory with its private DACL atomically.
// Inheritance is disabled at creation; no sensitive content is written in a broad-ACL window.
func MakePrivateDirectory(path string) error {
	if err := CheckPath(path, true); err != nil {
		return err
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
	sid, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	var descriptor uintptr
	ok, _, callErr := convertSDDL.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return errors.New("cannot create private security descriptor: " + callErr.Error())
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	attributes := syscall.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return syscall.CreateDirectory(name, &attributes)
}

func reparse(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	a, err := syscall.GetFileAttributes(p)
	return err != nil || a&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
