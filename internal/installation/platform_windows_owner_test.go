//go:build windows

package installation

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

var testConvertSecurity = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var testDescriptorOwner = advapi.NewProc("GetSecurityDescriptorOwner")
var testDescriptorDACL = advapi.NewProc("GetSecurityDescriptorDacl")
var testSecurityString = advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")

func testCurrentSID(t *testing.T) string {
	t.Helper()
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	return self
}

func testSecurityDescriptor(t *testing.T, sddl string) (unsafe.Pointer, *syscall.SID, *aclHeader) {
	t.Helper()
	text, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor unsafe.Pointer
	ok, _, callErr := testConvertSecurity.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatalf("parse synthetic SDDL: %v", callErr)
	}
	t.Cleanup(func() { syscall.LocalFree(syscall.Handle(uintptr(descriptor))) })
	var owner *syscall.SID
	var defaulted, present uint32
	ok, _, callErr = testDescriptorOwner.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 {
		t.Fatalf("read synthetic owner: %v", callErr)
	}
	var dacl *aclHeader
	ok, _, callErr = testDescriptorDACL.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 {
		t.Fatalf("read synthetic DACL: %v", callErr)
	}
	if present == 0 {
		dacl = nil
	}
	return descriptor, owner, dacl
}

func testDescriptorText(t *testing.T, descriptor unsafe.Pointer) string {
	t.Helper()
	var text *uint16
	var size uint32
	ok, _, callErr := testSecurityString.Call(uintptr(descriptor), 1, 1|4, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || text == nil || size == 0 || size > 1<<20 {
		t.Fatalf("read security descriptor text: %v", callErr)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(text))))
	return syscall.UTF16ToString(unsafe.Slice(text, int(size)))
}

func TestWindowsPrivateSecurityRequiresTrustedOwner(t *testing.T) {
	self := testCurrentSID(t)
	allowed := "D:P(A;;FA;;;" + self + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	foreign := "S-1-5-21-111111111-222222222-333333333-4242"
	if foreign == self {
		t.Fatal("synthetic foreign SID unexpectedly matches the current user")
	}
	for _, tc := range []struct {
		name, owner string
		accept      bool
	}{
		{"current-user", self, true},
		{"system", "SY", true},
		{"administrators", "BA", true},
		{"foreign-user-with-allowed-dacl", foreign, false},
		{"ordinary-users-group-with-allowed-dacl", "BU", false},
		{"missing-owner-with-allowed-dacl", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sddl := allowed
			if tc.owner != "" {
				sddl = "O:" + tc.owner + sddl
			}
			descriptor, owner, dacl := testSecurityDescriptor(t, sddl)
			before := testDescriptorText(t, descriptor)
			err := validatePrivateSecurity(owner, dacl, self)
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%t: %v", tc.accept, err)
			}
			if !tc.accept && !strings.Contains(err.Error(), "owner") {
				t.Fatalf("foreign ownership did not produce an owner diagnostic: %v", err)
			}
			if after := testDescriptorText(t, descriptor); after != before {
				t.Fatal("validation changed the descriptor")
			}
		})
	}
}

func TestWindowsTrustedOwnerDoesNotBypassDACLChecks(t *testing.T) {
	self := testCurrentSID(t)
	for _, daclText := range []string{"D:P(A;;FA;;;WD)", "D:P", ""} {
		_, owner, dacl := testSecurityDescriptor(t, "O:"+self+daclText)
		if err := validatePrivateSecurity(owner, dacl, self); err == nil {
			t.Fatalf("trusted owner bypassed unsafe DACL %q", daclText)
		}
	}
}

func testPathSecurityText(t *testing.T, path string) string {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var owner *syscall.SID
	var descriptor unsafe.Pointer
	status, _, _ := namedSecurity.Call(uintptr(unsafe.Pointer(name)), 1, 1|4, uintptr(unsafe.Pointer(&owner)), 0, 0, 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 {
		t.Fatal(syscall.Errno(status))
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	if owner == nil {
		t.Fatal("created private path has no owner")
	}
	actualOwner, err := owner.String()
	if err != nil || actualOwner != testCurrentSID(t) {
		t.Fatalf("created private path is not owned by the current user: %v", err)
	}
	return testDescriptorText(t, descriptor)
}

func TestWindowsCurrentOwnerPrivatePathsRemainUnchanged(t *testing.T) {
	self := testCurrentSID(t)
	descriptor, owner, _ := testSecurityDescriptor(t, "O:"+self+"D:P(A;OICI;FA;;;"+self+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	got, err := owner.String()
	if err != nil || got != self {
		t.Fatal("fixture does not belong to the current user")
	}
	attributes := syscall.SecurityAttributes{SecurityDescriptor: uintptr(descriptor)}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	dir := filepath.Join(t.TempDir(), "private-current-owner")
	name, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "private.txt")
	name, err = syscall.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, &attributes, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("synthetic private content"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		path      string
		directory bool
	}{{dir, true}, {file, false}} {
		before := testPathSecurityText(t, entry.path)
		if err := ValidatePrivatePath(entry.path, entry.directory); err != nil {
			t.Fatalf("current-user private path refused: %v", err)
		}
		if after := testPathSecurityText(t, entry.path); after != before {
			t.Fatal("validation rewrote owner or ACL")
		}
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "synthetic private content" {
		t.Fatal("validation changed private file contents")
	}
}
