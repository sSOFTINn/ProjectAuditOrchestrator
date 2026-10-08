package adapter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixtureMatrixRequiresEveryDeclaredCase(t *testing.T) {
	root := t.TempDir()
	for _, name := range fixtureManifest().FixtureCases {
		if err := os.WriteFile(filepath.Join(root, name+".expected.json"), []byte(`{"status":"FAILED","media_type":"application/json"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	matrix, err := LoadFixtureMatrix(root, fixtureManifest())
	if err != nil || len(matrix) != 5 || SortedFixtureNames(matrix)[0] != "empty" {
		t.Fatalf("fixture matrix invalid: %#v %v", matrix, err)
	}
	if err := os.Remove(filepath.Join(root, "malformed.expected.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFixtureMatrix(root, fixtureManifest()); err == nil {
		t.Fatal("incomplete fixture matrix was accepted")
	}
}

func TestAdapterFixtureExpectationsAreComplete(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"grype", "osv-scanner", "trivy", "gitleaks", "scancode", "reuse", "opengrep", "zizmor"} {
		t.Run(id, func(t *testing.T) {
			manifest, err := LoadFile(filepath.Join(repo, "adapters", id, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			matrix, err := LoadFixtureMatrix(filepath.Join(repo, "testdata", "scanner-outputs", id), manifest)
			if err != nil || len(matrix) != 5 {
				t.Fatalf("fixture matrix invalid: %#v %v", matrix, err)
			}
		})
	}
}
