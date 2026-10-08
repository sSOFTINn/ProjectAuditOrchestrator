package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func syntheticInputCapsule(t *testing.T, adapterID, kind string) (string, string) {
	t.Helper()
	root := t.TempDir()
	contents := []byte("rules:\n  - id: fixture\n")
	if err := os.WriteFile(filepath.Join(root, "rules.yml"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	fileSum := sha256.Sum256(contents)
	manifest := inputCapsuleManifest{
		APIVersion: "pao.dev/input-capsule/v1alpha1",
		AdapterID:  adapterID,
		Kind:       kind,
		Files:      []inputCapsuleFile{{Path: "rules.yml", SHA256: hex.EncodeToString(fileSum[:])}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, inputCapsuleManifestName), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(encoded)
	return root, "sha256:" + hex.EncodeToString(manifestSum[:])
}

func TestVerifyInputCapsuleBindsKindIdentityAndFiles(t *testing.T) {
	root, digest := syntheticInputCapsule(t, "opengrep", "rule-pack")
	if err := VerifyInputCapsule(root, digest, "opengrep", "rule-pack"); err != nil {
		t.Fatalf("valid input capsule rejected: %v", err)
	}
	if err := VerifyInputCapsule(root, digest, "opengrep", "license-data"); err == nil {
		t.Fatal("input capsule was accepted for the wrong kind")
	}
	if err := os.WriteFile(filepath.Join(root, "rules.yml"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInputCapsule(root, digest, "opengrep", "rule-pack"); err == nil {
		t.Fatal("tampered input capsule was accepted")
	}
}
