//go:build windows

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeclaredOutputReaderRejectsJunctionAncestor(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "result.json"), []byte(`{"private":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "redirect")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("create exact synthetic junction: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(junction); err != nil {
			t.Error(err)
		}
	})
	if data, err := readDeclaredOutput(root, "redirect/result.json"); err == nil || data != nil {
		t.Fatal("declared output followed a Windows junction ancestor")
	}
}
