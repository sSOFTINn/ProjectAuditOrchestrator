//go:build windows

package auditconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateDirectoryRejectsBroadInheritedACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := MakePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := MakePrivateDirectory(dir); err == nil {
		t.Fatal("overwrote existing directory")
	}
	// Quote the generated fixture path as a PowerShell single-quoted literal.
	script := `$paoAcl=[System.IO.Directory]::GetAccessControl('` + strings.ReplaceAll(dir, "'", "''") + `'); if(-not $paoAcl.AreAccessRulesProtected){throw 'inherited DACL'}; foreach($paoRule in $paoAcl.Access){if($paoRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')){throw 'broad ACL'}}; 'PRIVATE'`
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("read ACL: %v: %s", err, output)
	}
	if strings.TrimSpace(string(output)) != "PRIVATE" {
		t.Fatal("private access was not verified")
	}
}

func TestWindowsPathAliasesRejected(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"out.", "out ", "file:stream", "NUL", "COM1.txt"} {
		if err := CheckPath(filepath.Join(root, name), true); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestWindowsJunctionAncestorRejected(t *testing.T) {
	root := t.TempDir()
	real, link := filepath.Join(root, "real"), filepath.Join(root, "junction")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Fatalf("create synthetic junction: %v %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil {
			t.Error(err)
		}
	})
	if err := CheckPath(filepath.Join(link, "future"), true); err == nil {
		t.Fatal("accepted junction ancestor")
	}
}
