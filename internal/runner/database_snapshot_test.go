package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDatabaseSnapshot(t *testing.T) {
	root := t.TempDir()
	data := []byte("offline database")
	if err := os.MkdirAll(filepath.Join(root, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db", "data.bin"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	dataSum := sha256.Sum256(data)
	metadata := []byte(`{"schema":"pao.dev/toolchain-database-metadata/v1","tool":"fixture","files":[{"path":"db/data.bin","sha256":"` + hex.EncodeToString(dataSum[:]) + `"}]}`)
	if err := os.WriteFile(filepath.Join(root, databaseMetadataName), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	metadataSum := sha256.Sum256(metadata)
	if err := VerifyDatabaseSnapshot(root, "sha256:"+hex.EncodeToString(metadataSum[:]), "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db", "data.bin"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabaseSnapshot(root, "sha256:"+hex.EncodeToString(metadataSum[:]), "fixture"); err == nil {
		t.Fatal("expected changed database to fail closed")
	}
}
