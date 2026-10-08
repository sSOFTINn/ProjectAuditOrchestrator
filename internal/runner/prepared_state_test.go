package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func syntheticPreparedState(t *testing.T, adapterID string) (string, string) {
	t.Helper()
	root := t.TempDir()
	contents := []byte("synthetic-state")
	if err := os.WriteFile(filepath.Join(root, "cache.txt"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	fileSum := sha256.Sum256(contents)
	manifest := preparedStateManifest{APIVersion: "pao.dev/prepared-state/v1alpha1", AdapterID: adapterID, Files: []preparedStateFile{{Path: "cache.txt", SHA256: hex.EncodeToString(fileSum[:])}}}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, preparedStateManifestName), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(encoded)
	return root, "sha256:" + hex.EncodeToString(manifestSum[:])
}

func TestVerifyPreparedStateBindsManifestAndContents(t *testing.T) {
	root, digest := syntheticPreparedState(t, "fixture")
	if err := VerifyPreparedState(root, digest, "fixture"); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cache.txt"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreparedState(root, digest, "fixture"); err == nil {
		t.Fatal("tampered state was accepted")
	}
}

func TestVerifyPreparedStateRejectsAdapterMismatch(t *testing.T) {
	root, digest := syntheticPreparedState(t, "fixture")
	if err := VerifyPreparedState(root, digest, "other"); err == nil {
		t.Fatal("state for another adapter was accepted")
	}
}

func TestVerifyPreparedStateRejectsUnexpectedFile(t *testing.T) {
	root, digest := syntheticPreparedState(t, "fixture")
	if err := os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreparedState(root, digest, "fixture"); err == nil {
		t.Fatal("state with an unlisted file was accepted")
	}
}
