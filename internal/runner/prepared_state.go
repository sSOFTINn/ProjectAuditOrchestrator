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

const preparedStateManifestName = "pao-state-manifest.json"

type preparedStateManifest struct {
	APIVersion string              `json:"api_version"`
	AdapterID  string              `json:"adapter_id"`
	Files      []preparedStateFile `json:"files"`
}

type preparedStateFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifyPreparedState verifies an immutable, local state capsule before Docker receives its path.
// The expected digest binds the manifest; the manifest binds every regular file in the capsule.
func VerifyPreparedState(statePath, expectedDigest, adapterID string) error {
	if statePath == "" {
		return nil
	}
	info, err := os.Lstat(statePath)
	if err != nil {
		return fmt.Errorf("read prepared state: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("prepared state must be a non-symlink directory")
	}
	manifestPath := filepath.Join(statePath, preparedStateManifestName)
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read prepared state manifest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(sum[:]) != expectedDigest {
		return errors.New("prepared state manifest digest mismatch")
	}
	var manifest preparedStateManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return fmt.Errorf("parse prepared state manifest: %w", err)
	}
	if manifest.APIVersion != "pao.dev/prepared-state/v1alpha1" || manifest.AdapterID != adapterID || len(manifest.Files) == 0 {
		return errors.New("prepared state manifest identity is invalid")
	}
	expected := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "\\") || entry.Path == preparedStateManifestName || !sha256Reference.MatchString("sha256:"+entry.SHA256) {
			return errors.New("prepared state manifest contains an unsafe file entry")
		}
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("prepared state manifest contains a path escape")
		}
		if _, exists := expected[clean]; exists {
			return errors.New("prepared state manifest contains a duplicate file entry")
		}
		expected[clean] = entry.SHA256
	}
	observed := map[string]string{}
	err = filepath.WalkDir(statePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("prepared state cannot contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(statePath, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == preparedStateManifestName {
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
		return fmt.Errorf("inspect prepared state: %w", err)
	}
	if len(observed) != len(expected) {
		return errors.New("prepared state file set does not match manifest")
	}
	for path, digest := range expected {
		if observed[path] != digest {
			return fmt.Errorf("prepared state file digest mismatch: %s", path)
		}
	}
	return nil
}
