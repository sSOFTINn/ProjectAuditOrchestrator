package target

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSnapshotRetainsConfirmedDigestForUnchangedTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotRootWithBudgetContext(context.Background(), root, 3, 1, 3)
	if err != nil || !snapshot.Complete || snapshot.ManifestHash != "e4f28e4cf0b113124c9e46711ccde368b60676a680e617a1b16af82b4ce7dd28" || snapshot.TargetID != "sha256:2765af2f6a3a7d5af8f0abc7d340b41313c3ceff261d634b8f367b326731a391" {
		t.Fatalf("unchanged target digest contract drifted: %#v %v", snapshot, err)
	}
}

func TestSnapshotEntryLimitCountsDirectoriesAndStopsWholeWalk(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"first", "second", "third"} {
		if err := os.Mkdir(filepath.Join(root, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	limited, err := SnapshotRootWithBudget(root, 8, 2, 8)
	if err != nil || limited.Complete || len(limited.Files) != 0 {
		t.Fatalf("directory entries did not consume budget: %#v %v", limited, err)
	}
	complete, err := SnapshotRootWithBudget(root, 8, 3, 8)
	if err != nil || !complete.Complete {
		t.Fatalf("exact entry limit should allow an unchanged tree: %#v %v", complete, err)
	}
}

func TestSnapshotTotalLimitStopsNestedAndFollowingFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "first"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"first/a.bin", "first/b.bin", "tail.bin"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), []byte("four"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := SnapshotRootWithBudget(root, 4, 4, 4)
	if err != nil || snapshot.Complete || len(snapshot.Files) != 2 || snapshot.Files[1].Path != "first/b.bin" || snapshot.Files[1].Status != "SKIPPED_TOTAL_LIMIT" {
		t.Fatalf("byte budget did not stop the entire tree: %#v %v", snapshot, err)
	}
}

func TestSnapshotContextCancellationIsPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SnapshotRootContext(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
}

func TestSnapshotRefreshesWindowsDirectoryEntryMetadata(t *testing.T) {
	// Nested writes can leave cached Windows DirEntry timestamps behind a fresh
	// path stat. Identity must remain checked while fresh metadata sets baseline.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "demo.yml"), []byte("name: fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotRoot(root)
	if err != nil || !snapshot.Complete || len(snapshot.Files) != 2 {
		t.Fatalf("unchanged nested fixture was rejected: %#v %v", snapshot, err)
	}
}

func TestSnapshotIsDeterministicAndSkipsGit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestHash != second.ManifestHash || first.TargetID != second.TargetID {
		t.Fatalf("non-deterministic snapshot: %#v %#v", first, second)
	}
	if len(first.Files) != 2 || first.Files[0].Path != "a.txt" {
		t.Fatalf("unexpected files: %#v", first.Files)
	}
}

func TestSnapshotDoesNotExecuteGitForMetadata(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	runGitTest(t, root, "init", "-q")
	runGitTest(t, root, "config", "user.name", "PAO fixture")
	runGitTest(t, root, "config", "user.email", "fixture@example.test")
	path := filepath.Join(root, "fixture.txt")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, root, "add", "fixture.txt")
	runGitTest(t, root, "commit", "-qm", "fixture")
	clean, err := SnapshotRoot(root)
	if err != nil || clean.VCS.System != "git" || clean.VCS.Status != "UNAVAILABLE" || clean.VCS.Dirty != "UNKNOWN" || clean.VCS.Commit != "" {
		t.Fatalf("snapshot unexpectedly used Git metadata: %#v %v", clean.VCS, err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirty, err := SnapshotRoot(root)
	if err != nil || dirty.VCS.Status != "UNAVAILABLE" || dirty.TargetID == clean.TargetID {
		t.Fatalf("file change was not captured without Git execution: %#v %v", dirty.VCS, err)
	}
}

func runGitTest(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func TestSnapshotMarksOversizedFileIncomplete(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.bin"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := SnapshotRootWithLimits(root, 4, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s.Complete || s.Files[0].Status != "SKIPPED_SIZE_LIMIT" {
		t.Fatalf("expected incomplete size-limited snapshot: %#v", s)
	}
}

func TestSnapshotStopsAtTotalByteBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "first.bin"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "second.bin"), []byte("5678"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotRootWithBudget(root, 4, 10, 4)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Complete || len(snapshot.Files) != 2 || snapshot.Files[1].Status != "SKIPPED_TOTAL_LIMIT" {
		t.Fatalf("total-byte budget was not enforced: %#v", snapshot)
	}
}

func TestIsInside(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if !IsInside(root, filepath.Join(root, "child")) || IsInside(root, filepath.Join(root, "..", "outside")) {
		t.Fatal("path boundary check failed")
	}
}

func TestSafeRelativeRejectsTraversalAndRetainsPortablePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	inside := filepath.Join(root, "nested", "file.txt")
	if got, err := SafeRelative(root, inside); err != nil || got != "nested/file.txt" {
		t.Fatalf("inside path was not normalized safely: %q %v", got, err)
	}
	if _, err := SafeRelative(root, filepath.Join(root, "..", "outside.txt")); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestSnapshotDoesNotFollowSymlinkOutsideTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable on this runner: %v", err)
	}
	snapshot, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Files) != 0 || len(snapshot.ReparsePaths) != 1 || snapshot.ReparsePaths[0] != "outside-link" {
		t.Fatalf("link escape was followed or not recorded: %#v", snapshot)
	}
}
