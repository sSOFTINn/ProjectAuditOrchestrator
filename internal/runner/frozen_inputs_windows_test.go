//go:build windows

package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsFrozenCopiesDenyWriteAndRenameUntilCleanup(t *testing.T) {
	spec, limits, _ := frozenFixture(t)
	frozen, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	for _, path := range []string{frozen.ToolPath, frozen.InputPath, filepath.Join(frozen.StatePath, "bin", "entrypoint"), filepath.Join(frozen.DatabasePath, "db", "data.bin"), filepath.Join(frozen.RulePackPath, "rules.yml")} {
		if err := os.WriteFile(path, []byte("unapproved"), 0o600); err == nil {
			t.Fatalf("write succeeded through held frozen handle: %s", filepath.Base(path))
		}
		if err := os.Rename(path, path+"-moved"); err == nil {
			_ = os.Rename(path+"-moved", path)
			t.Fatalf("rename succeeded through held frozen handle: %s", filepath.Base(path))
		}
	}
	base := filepath.Dir(filepath.Dir(frozen.ToolPath))
	if err := os.Rename(base, base+"-moved"); err == nil {
		_ = os.Rename(base+"-moved", base)
		t.Fatal("frozen ancestor was renamed while pinned")
	}
	assertFrozenFixture(t, frozen)
}

func TestWindowsPinExecutableKeepsOriginalLayoutAndExcludesWriters(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "native", "inert.exe")
	digest := frozenWriteTestFile(t, path, []byte("approved-native"), 0o755)
	cleanup, err := PinExecutable(context.Background(), path, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := os.WriteFile(path, []byte("unapproved"), 0o600); err == nil {
		t.Fatal("native executable changed while pinned")
	}
	if err := os.Rename(filepath.Dir(path), filepath.Join(root, "replacement")); err == nil {
		_ = os.Rename(filepath.Join(root, "replacement"), filepath.Dir(path))
		t.Fatal("native executable ancestor changed while pinned")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("legitimate-update-after-release"), 0o600); err != nil {
		t.Fatalf("pin cleanup retained write denial: %v", err)
	}
}

func TestWindowsFreezeInputsRefusesJunctionAtValidationBarrier(t *testing.T) {
	spec, limits, sources := frozenFixture(t)
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "tool", "scanner")
	frozenWriteTestFile(t, marker, []byte("outside-only-marker"), 0o755)
	if err := os.Rename(sources, sources+"-previous"); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", sources, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v %s", err, output)
	}
	defer func() {
		if err := os.Remove(sources); err != nil {
			t.Error(err)
		}
	}()
	if _, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits); err == nil || cleanup != nil {
		t.Fatalf("junction ancestor was admitted after validation: %v", err)
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "outside-only-marker" {
		t.Fatalf("outside marker changed: %q %v", content, err)
	}
	created, err := filepath.Glob(filepath.Join(filepath.Dir(spec.TemporaryDir), ".pao-frozen-*"))
	if err != nil || len(created) != 0 {
		t.Fatalf("junction refusal created private inputs: %v %v", created, err)
	}
}

func TestWindowsFrozenRootUsesPrivateProtectedDACL(t *testing.T) {
	spec, limits, _ := frozenFixture(t)
	frozen, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	base := filepath.Dir(filepath.Dir(frozen.ToolPath))
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if !filepath.IsAbs(powershell) {
		t.Skip("absolute Windows PowerShell unavailable")
	}
	quoted := strings.ReplaceAll(base, "'", "''")
	script := "$ErrorActionPreference='Stop'; $acl=[System.IO.Directory]::GetAccessControl('" + quoted + "'); if(-not $acl.AreAccessRulesProtected){throw 'unprotected ACL'}; foreach($rule in $acl.Access){if($rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')){throw 'broad ACL'}}; 'PRIVATE'"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, powershell, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "PRIVATE" {
		t.Fatalf("frozen root privacy was not verified: %q %v", output, err)
	}
}
