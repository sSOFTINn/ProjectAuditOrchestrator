package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const databaseMetadataName = "metadata.json"

type databaseMetadata struct {
	Schema          string             `json:"schema"`
	Tool            string             `json:"tool"`
	Files           []databaseFileHash `json:"files"`
	SupportingFiles []databaseFileHash `json:"supporting_files,omitempty"`
}

type databaseFileHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifyDatabaseSnapshot binds a read-only offline database directory to its
// metadata digest and verifies the complete declared file set before mounting.
func VerifyDatabaseSnapshot(root, expectedDigest, toolID string) error {
	if root == "" {
		return nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("read database snapshot: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("database snapshot must be a non-symlink directory")
	}
	encoded, err := os.ReadFile(filepath.Join(root, databaseMetadataName))
	if err != nil {
		return fmt.Errorf("read database metadata: %w", err)
	}
	sum := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(sum[:]) != expectedDigest {
		return errors.New("database metadata digest mismatch")
	}
	var metadata databaseMetadata
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return fmt.Errorf("parse database metadata: %w", err)
	}
	if metadata.Schema != "pao.dev/toolchain-database-metadata/v1" || metadata.Tool != toolID || len(metadata.Files) == 0 {
		return errors.New("database metadata identity is invalid")
	}
	entries := append(append([]databaseFileHash(nil), metadata.Files...), metadata.SupportingFiles...)
	expected := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "\\") || !sha256Reference.MatchString("sha256:"+entry.SHA256) {
			return errors.New("database metadata contains an unsafe file entry")
		}
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean == databaseMetadataName {
			return errors.New("database metadata contains a path escape")
		}
		if _, exists := expected[clean]; exists {
			return errors.New("database metadata contains a duplicate file entry")
		}
		expected[clean] = entry.SHA256
	}
	observed := map[string]string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("database snapshot cannot contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == databaseMetadataName {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fileSum := sha256.Sum256(contents)
		observed[rel] = hex.EncodeToString(fileSum[:])
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect database snapshot: %w", err)
	}
	if len(observed) != len(expected) {
		return errors.New("database snapshot file set does not match metadata")
	}
	for path, digest := range expected {
		if observed[path] != digest {
			return fmt.Errorf("database snapshot file digest mismatch: %s", path)
		}
	}
	return nil
}
