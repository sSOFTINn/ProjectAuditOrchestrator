package syft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestSyntheticFixtureMatrixPreservesRawEvidence(t *testing.T) {
	cases := map[string]string{
		"success.json":   "SUCCEEDED",
		"empty.json":     "NO_FINDINGS",
		"partial.json":   "PARTIAL",
		"error.json":     "FAILED",
		"malformed.json": "FAILED",
	}
	for fixture, wantStatus := range cases {
		t.Run(fixture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scanner-outputs", "syft", fixture))
			if err != nil {
				t.Fatal(err)
			}
			store, err := artifact.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			rawArtifact, result, err := Ingest(store, raw, "fixture-"+fixture)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != wantStatus || rawArtifact.SHA256 == "" {
				t.Fatalf("unexpected fixture result: %#v %#v", result, rawArtifact)
			}
			if _, err := os.Stat(filepath.Join(store.Root(), filepath.FromSlash(rawArtifact.Path))); err != nil {
				t.Fatalf("raw output was not retained: %v", err)
			}
		})
	}
}

func TestManifestAndExecutionSpecUseStrongIsolation(t *testing.T) {
	if err := Manifest().Validate(); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := adapter.LoadFile(path)
	if err != nil || loaded.ID != Manifest().ID || loaded.ParserSchema != Manifest().ParserSchema {
		t.Fatalf("manifest file diverged from adapter contract: %#v %v", loaded, err)
	}
	root := t.TempDir()
	spec := ExecutionSpec(filepath.Join(root, "syft"), root, t.TempDir())
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
}
