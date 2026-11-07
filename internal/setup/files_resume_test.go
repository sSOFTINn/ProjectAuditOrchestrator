package setup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFailedCopyCanResumeWithoutReplacingInstalledBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := privateTree(root); err != nil {
		t.Fatal(err)
	}
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "installed")
	good := []byte("complete pinned public artifact")
	if err := os.WriteFile(source, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyExact(source, destination, hashBytes(good), 1024); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("failed copy poisoned destination")
	}
	// A killed process may retain a scratch file. It must not block resumption.
	if err := os.WriteFile(filepath.Join(root, ".pao-copy-interrupted.partial"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyExact(source, destination, hashBytes(good), 1024); err != nil {
		t.Fatal(err)
	}
	if err := copyExact(source, destination, hashBytes(good), 1024); err != nil {
		t.Fatal("verified resume:", err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyExact(source, destination, hashBytes([]byte("replacement")), 1024); err == nil {
		t.Fatal("existing bytes replaced")
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != string(good) {
		t.Fatalf("installed bytes changed: %v", err)
	}
}

func TestPublishAndWriteOnceNeverClobberExistingFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := privateTree(root); err != nil {
		t.Fatal(err)
	}
	dest, scratch := filepath.Join(root, "record.json"), filepath.Join(root, "scratch")
	if err := writeOnce(dest, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := writeOnce(dest, []byte("changed")); err == nil {
		t.Fatal("record overwritten")
	}
	if err := os.WriteFile(scratch, []byte("raced"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishFile(scratch, dest); err == nil {
		t.Fatal("publish clobbered existing record")
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "original" {
		t.Fatalf("existing record changed: %v", err)
	}
}
