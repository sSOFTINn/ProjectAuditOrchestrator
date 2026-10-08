// Package artifact owns PAO's protected, content-addressed raw evidence store.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const rawPrefix = "raw/sha256"

const DefaultMaxRawBytes int64 = 64 << 20

// RawArtifact identifies immutable native scanner output. Path is always relative to the
// store root so absolute local paths are not exported into portable reports.
type RawArtifact struct {
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	MediaType   string `json:"media_type"`
	ExecutionID string `json:"execution_id"`
	Path        string `json:"path"`
}

// Event is an append-only journal record. Callers supply any run timestamp explicitly so the
// content-addressed core does not obtain time from the ambient machine clock.
type Event struct {
	Type        string `json:"type"`
	ExecutionID string `json:"execution_id,omitempty"`
	Artifact    string `json:"artifact,omitempty"`
	Status      string `json:"status"`
}

type Store struct {
	root        string
	maxRawBytes int64
}

func Open(root string) (*Store, error) {
	return OpenWithLimit(root, DefaultMaxRawBytes)
}

func OpenWithLimit(root string, maxRawBytes int64) (*Store, error) {
	if root == "" {
		return nil, errors.New("artifact store root is required")
	}
	if maxRawBytes <= 0 {
		return nil, errors.New("raw artifact size limit must be positive")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact store: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("artifact store root must not be a symbolic link or reparse point")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect artifact store root: %w", err)
	}
	for _, dir := range []string{filepath.Join(abs, "raw", "sha256"), filepath.Join(abs, "journal")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create artifact store: %w", err)
		}
	}
	for _, dir := range []string{abs, filepath.Join(abs, "raw"), filepath.Join(abs, "raw", "sha256"), filepath.Join(abs, "journal")} {
		if err := requireRealDirectory(dir); err != nil {
			return nil, err
		}
	}
	return &Store{root: abs, maxRawBytes: maxRawBytes}, nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect artifact store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("artifact store path must be a real directory: %s", path)
	}
	return nil
}

func (s *Store) Root() string { return s.root }

// PutRaw saves bytes once under their SHA-256 address. Existing evidence is verified and never
// overwritten, even when a caller presents a different media type or execution ID.
func (s *Store) PutRaw(mediaType string, content []byte, executionID string) (RawArtifact, error) {
	if s == nil || s.root == "" {
		return RawArtifact{}, errors.New("artifact store is not open")
	}
	if mediaType == "" || strings.ContainsRune(mediaType, '\x00') {
		return RawArtifact{}, errors.New("safe media type is required")
	}
	if strings.ContainsRune(executionID, '\x00') {
		return RawArtifact{}, errors.New("execution ID contains NUL")
	}
	if int64(len(content)) > s.maxRawBytes {
		return RawArtifact{}, fmt.Errorf("raw artifact exceeds configured size limit of %d bytes", s.maxRawBytes)
	}
	digest := sha256.Sum256(content)
	hexDigest := hex.EncodeToString(digest[:])
	rel := filepath.ToSlash(filepath.Join(rawPrefix, hexDigest))
	destination := filepath.Join(s.root, filepath.FromSlash(rel))

	if err := writeOnce(destination, content, hexDigest); err != nil {
		return RawArtifact{}, err
	}
	artifact := RawArtifact{SHA256: "sha256:" + hexDigest, Size: int64(len(content)), MediaType: mediaType, ExecutionID: executionID, Path: rel}
	if err := s.Append(Event{Type: "RAW_ARTIFACT_STORED", ExecutionID: executionID, Artifact: artifact.SHA256, Status: "SUCCEEDED"}); err != nil {
		return RawArtifact{}, err
	}
	return artifact, nil
}

func writeOnce(destination string, content []byte, expectedDigest string) error {
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("artifact address is not a regular file: %s", destination)
		}
		return verifyDigest(destination, expectedDigest)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect artifact address: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(destination), ".raw-*")
	if err != nil {
		return fmt.Errorf("create temporary raw artifact: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("protect temporary raw artifact: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return fmt.Errorf("write raw artifact: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync raw artifact: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close raw artifact: %w", err)
	}
	if err := os.Rename(tempName, destination); err != nil {
		if os.IsExist(err) {
			return verifyDigest(destination, expectedDigest)
		}
		return fmt.Errorf("publish raw artifact: %w", err)
	}
	if err := os.Chmod(destination, 0o400); err != nil {
		return fmt.Errorf("protect raw artifact: %w", err)
	}
	return nil
}

func verifyDigest(path, expectedDigest string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read existing raw artifact: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return fmt.Errorf("existing raw artifact digest mismatch: %s", path)
	}
	return nil
}

// Append writes one JSON object per line. It intentionally has no truncate or rewrite API.
func (s *Store) Append(event Event) error {
	if s == nil || s.root == "" {
		return errors.New("artifact store is not open")
	}
	if event.Type == "" || event.Status == "" {
		return errors.New("event type and status are required")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode artifact event: %w", err)
	}
	journal := filepath.Join(s.root, "journal", "events.jsonl")
	if info, err := os.Lstat(journal); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("event journal is not a regular file: %s", journal)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect event journal: %w", err)
	}
	f, err := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open event journal: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("append artifact event: %w", err)
	}
	return f.Sync()
}
