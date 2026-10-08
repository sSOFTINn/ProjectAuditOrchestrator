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

const inputCapsuleManifestName = "pao-input-manifest.json"

type inputCapsuleManifest struct {
	APIVersion string             `json:"api_version"`
	AdapterID  string             `json:"adapter_id"`
	Kind       string             `json:"kind"`
	Files      []inputCapsuleFile `json:"files"`
}

type inputCapsuleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifyInputCapsule binds an adapter to an immutable, read-only external input such as a rule pack.
func VerifyInputCapsule(root, expectedDigest, adapterID, kind string) error {
	if root == "" {
		return nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("read input capsule: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("input capsule must be a non-symlink directory")
	}
	manifestPath := filepath.Join(root, inputCapsuleManifestName)
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read input capsule manifest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(sum[:]) != expectedDigest {
		return errors.New("input capsule manifest digest mismatch")
	}
	var manifest inputCapsuleManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return fmt.Errorf("parse input capsule manifest: %w", err)
	}
	if manifest.APIVersion != "pao.dev/input-capsule/v1alpha1" || manifest.AdapterID != adapterID || manifest.Kind != kind || len(manifest.Files) == 0 {
		return errors.New("input capsule manifest identity is invalid")
	}
	expected := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "\\") || entry.Path == inputCapsuleManifestName || !sha256Reference.MatchString("sha256:"+entry.SHA256) {
			return errors.New("input capsule manifest contains an unsafe file entry")
		}
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("input capsule manifest contains a path escape")
		}
		if _, exists := expected[clean]; exists {
			return errors.New("input capsule manifest contains a duplicate file entry")
		}
		expected[clean] = entry.SHA256
	}
	observed := map[string]string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("input capsule cannot contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == inputCapsuleManifestName {
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
		return fmt.Errorf("inspect input capsule: %w", err)
	}
	if len(observed) != len(expected) {
		return errors.New("input capsule file set does not match manifest")
	}
	for path, digest := range expected {
		if observed[path] != digest {
			return fmt.Errorf("input capsule file digest mismatch: %s", path)
		}
	}
	return nil
}
