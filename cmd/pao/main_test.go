package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

func TestSnapshotCommandInputDoesNotMutateTarget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go.mod")
	if err := os.WriteFile(path, []byte("module fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := target.SnapshotRoot(root)
	if err != nil || !s.Complete {
		t.Fatalf("snapshot failed: %v %#v", err, s)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("target changed during inspection")
	}
}
