package adapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
)

func TestIngestRawFirstRetainsMalformedAndIsolatesArtifacts(t *testing.T) {
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, firstResult, err := IngestRawFirst(store, "exec-one", "application/json", []byte("not-json"), func([]byte) ParsedResult { return ParsedResult{Status: "FAILED", Reason: "malformed"} })
	if err != nil || firstResult.Status != "FAILED" {
		t.Fatalf("malformed output was not retained as failed: %#v %v", firstResult, err)
	}
	second, secondResult, err := IngestRawFirst(store, "exec-two", "application/json", []byte(`{"ok":true}`), func([]byte) ParsedResult { return ParsedResult{Status: "NO_FINDINGS"} })
	if err != nil || secondResult.Status != "NO_FINDINGS" || first.SHA256 == second.SHA256 {
		t.Fatalf("independent output was not retained: %#v %#v %v", first, second, err)
	}
	if _, err := os.Stat(filepath.Join(store.Root(), filepath.FromSlash(first.Path))); err != nil {
		t.Fatalf("malformed raw evidence was lost: %v", err)
	}
}

func TestIngestRawFirstConvertsParserPanicToFailure(t *testing.T) {
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, result, err := IngestRawFirst(store, "exec-panic", "application/json", []byte(`{}`), func([]byte) ParsedResult { panic("fixture") })
	if err != nil || result.Status != "FAILED" {
		t.Fatalf("parser panic was not fail-closed: %#v %v", result, err)
	}
}
