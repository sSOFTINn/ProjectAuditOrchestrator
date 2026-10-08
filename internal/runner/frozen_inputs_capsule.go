package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func (s *frozenSession) readManifest(ctx context.Context, path string) ([]byte, error) {
	file, err := frozenOpenPath(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > s.limits.MaxManifestBytes {
		return nil, errors.New("frozen input manifest exceeds parsing limit")
	}
	var content bytes.Buffer
	if err := s.copyExactly(ctx, &content, file, info.Size(), false); err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}

func (s *frozenSession) verifyCapsule(ctx context.Context, root, kind, digest, adapterID string, observed map[string]frozenFile) error {
	manifestName := ""
	switch kind {
	case "state":
		manifestName = preparedStateManifestName
	case "database":
		manifestName = databaseMetadataName
	case "rules":
		manifestName = inputCapsuleManifestName
	default:
		return errors.New("unknown frozen input capsule kind")
	}
	manifest, exists := observed[manifestName]
	if !exists || manifest.digest != digest {
		return fmt.Errorf("%s frozen manifest digest mismatch", kind)
	}
	content, err := s.readManifest(ctx, filepath.Join(root, manifestName))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return errors.New("frozen manifest changed after readback")
	}
	var entries []preparedStateFile
	switch kind {
	case "state":
		var decoded preparedStateManifest
		if err := json.Unmarshal(content, &decoded); err != nil {
			return err
		}
		if decoded.APIVersion != "pao.dev/prepared-state/v1alpha1" || decoded.AdapterID != adapterID || len(decoded.Files) == 0 {
			return errors.New("frozen prepared-state identity mismatch")
		}
		entries = decoded.Files
	case "database":
		var decoded databaseMetadata
		if err := json.Unmarshal(content, &decoded); err != nil {
			return err
		}
		if decoded.Schema != "pao.dev/toolchain-database-metadata/v1" || decoded.Tool != adapterID || len(decoded.Files) == 0 {
			return errors.New("frozen database identity mismatch")
		}
		for _, entry := range append(decoded.Files, decoded.SupportingFiles...) {
			entries = append(entries, preparedStateFile{entry.Path, entry.SHA256})
		}
	case "rules":
		var decoded inputCapsuleManifest
		if err := json.Unmarshal(content, &decoded); err != nil {
			return err
		}
		if decoded.APIVersion != "pao.dev/input-capsule/v1alpha1" || decoded.AdapterID != adapterID || decoded.Kind != "rule-pack" || len(decoded.Files) == 0 {
			return errors.New("frozen rule-pack identity mismatch")
		}
		for _, entry := range decoded.Files {
			entries = append(entries, preparedStateFile{entry.Path, entry.SHA256})
		}
	}
	if len(entries) > s.limits.MaxEntries || len(observed) != len(entries)+1 {
		return errors.New("frozen capsule file set does not match manifest")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "\\") || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean == manifestName || seen[clean] || !sha256Reference.MatchString("sha256:"+entry.SHA256) {
			return errors.New("frozen capsule contains unsafe or duplicate manifest entries")
		}
		seen[clean] = true
		file, exists := observed[clean]
		if !exists || file.digest != "sha256:"+entry.SHA256 {
			return fmt.Errorf("frozen capsule content digest mismatch: %s", clean)
		}
	}
	return ctx.Err()
}
