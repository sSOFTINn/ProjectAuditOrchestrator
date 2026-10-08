//go:build windows

package target

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSnapshotDoesNotFollowWindowsJunctionOutsideTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "sentinel.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "outside-junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable on this runner: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(junction); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove temporary junction: %v", err)
		}
	})

	snapshot, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Files) != 0 || len(snapshot.ReparsePaths) != 1 || snapshot.ReparsePaths[0] != "outside-junction" {
		t.Fatalf("junction escape was followed or not recorded: %#v", snapshot)
	}
}
