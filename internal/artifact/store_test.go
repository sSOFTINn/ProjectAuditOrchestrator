package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePreservesContentAddressedRawArtifact(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.PutRaw("application/json", []byte(`{"fixture":true}`), "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PutRaw("application/json", []byte(`{"fixture":true}`), "exec-2")
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 || first.Path != second.Path {
		t.Fatalf("same bytes must keep one stable address: %#v %#v", first, second)
	}
	if !strings.HasPrefix(first.Path, rawPrefix+"/") || filepath.IsAbs(first.Path) {
		t.Fatalf("artifact path is not portable: %#v", first)
	}
	content, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(first.Path)))
	if err != nil || string(content) != `{"fixture":true}` {
		t.Fatalf("stored raw evidence changed: %q %v", content, err)
	}
	different, err := store.PutRaw("application/json", []byte(`{"fixture":false}`), "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	if different.SHA256 == first.SHA256 {
		t.Fatal("different raw evidence reused an address")
	}
	journal, err := os.ReadFile(filepath.Join(store.Root(), "journal", "events.jsonl"))
	if err != nil || strings.Count(string(journal), "RAW_ARTIFACT_STORED") != 3 {
		t.Fatalf("append-only journal missing artifact records: %q %v", journal, err)
	}
}

func TestStoreRejectsUnsafeArtifactMetadata(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRaw("", []byte("fixture"), "exec"); err == nil {
		t.Fatal("empty media type accepted")
	}
	if _, err := store.PutRaw("text/plain", []byte("fixture"), "exec\x00bad"); err == nil {
		t.Fatal("NUL execution ID accepted")
	}
}

func TestStoreRejectsOutputBombBeforeWritingArtifact(t *testing.T) {
	store, err := OpenWithLimit(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRaw("application/json", []byte("12345"), "exec"); err == nil {
		t.Fatal("oversized raw output was accepted")
	}
	entries, err := os.ReadDir(filepath.Join(store.Root(), "raw", "sha256"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversized output left raw evidence behind: %#v %v", entries, err)
	}
}

func TestStoreRejectsJournalSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(store.Root(), "journal", "events.jsonl")
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.Symlink(outside, journal); err != nil {
		t.Skipf("symlink creation unavailable on this runner: %v", err)
	}
	if err := store.Append(Event{Type: "TEST", Status: "SUCCEEDED"}); err == nil {
		t.Fatal("journal symlink was accepted")
	}
}
