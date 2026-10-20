package target

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	DefaultMaxFileBytes = 64 << 20
	DefaultMaxEntries   = 100000
	// DefaultMaxFiles is retained for callers; the limit now bounds all entries.
	DefaultMaxFiles      = DefaultMaxEntries
	DefaultMaxTotalBytes = 4 << 30
)

type FileEntry struct {
	Path             string `json:"path"`
	Size             int64  `json:"size"`
	Mode             string `json:"mode"`
	SHA256           string `json:"sha256,omitempty"`
	Status           string `json:"status"`
	GoModDeclaration string `json:"go_mod_declaration,omitempty"`
}

type Snapshot struct {
	Root         string      `json:"root"`
	TargetID     string      `json:"target_id"`
	ManifestHash string      `json:"manifest_hash"`
	Complete     bool        `json:"complete"`
	Files        []FileEntry `json:"files"`
	ReparsePaths []string    `json:"reparse_paths,omitempty"`
	VCS          VCSState    `json:"vcs"`
}

type VCSState struct {
	System string `json:"system"`
	Commit string `json:"commit,omitempty"`
	Dirty  string `json:"dirty"`
	Status string `json:"status"`
}

func SnapshotRoot(root string) (Snapshot, error) {
	return SnapshotRootContext(context.Background(), root)
}

func SnapshotRootContext(ctx context.Context, root string) (Snapshot, error) {
	return SnapshotRootWithBudgetContext(ctx, root, DefaultMaxFileBytes, DefaultMaxEntries, DefaultMaxTotalBytes)
}

func SnapshotRootWithLimits(root string, maxFileBytes int64, maxFiles int) (Snapshot, error) {
	return SnapshotRootWithBudget(root, maxFileBytes, maxFiles, DefaultMaxTotalBytes)
}

func SnapshotRootWithBudget(root string, maxFileBytes int64, maxFiles int, maxTotalBytes int64) (Snapshot, error) {
	return SnapshotRootWithBudgetContext(context.Background(), root, maxFileBytes, maxFiles, maxTotalBytes)
}

// SnapshotRootWithBudgetContext applies byte limits while reading and bounds all
// tree entries, including directories, rather than only the recorded files.
func SnapshotRootWithBudgetContext(ctx context.Context, root string, maxFileBytes int64, maxEntries int, maxTotalBytes int64) (Snapshot, error) {
	if maxFileBytes <= 0 || maxEntries <= 0 || maxTotalBytes <= 0 {
		return Snapshot{}, errors.New("snapshot limits must be positive")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("resolve target: %w", err)
	}
	info, err := lstatIdentity(abs)
	if err != nil {
		return Snapshot{}, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() || isReparsePoint(abs) {
		return Snapshot{}, fmt.Errorf("target is not a directory: %s", abs)
	}

	s := Snapshot{Root: filepath.ToSlash(abs), Complete: true}
	budget := readBudget{remaining: maxTotalBytes}
	stop := errors.New("snapshot byte budget exhausted")
	err = walkBounded(ctx, abs, maxEntries, func(path string, entry fs.DirEntry, fi os.FileInfo) error {
		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			return relErr
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return fs.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 || isReparsePoint(path) {
			s.ReparsePaths = append(s.ReparsePaths, filepath.ToSlash(rel))
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		f := FileEntry{Path: filepath.ToSlash(rel), Size: fi.Size(), Mode: fi.Mode().String(), Status: "HASHED"}
		if fi.Size() > maxFileBytes {
			f.Status = "SKIPPED_SIZE_LIMIT"
			s.Complete = false
			s.Files = append(s.Files, f)
			return nil
		}
		if fi.Size() > budget.remaining {
			s.Complete = false
			f.Status = "SKIPPED_TOTAL_LIMIT"
			s.Files = append(s.Files, f)
			return stop
		}
		h := sha256.New()
		var declaration bytes.Buffer
		var destination io.Writer = h
		if entry.Name() == "go.mod" && fi.Size() <= MaxGoDeclarationBytes {
			destination = io.MultiWriter(h, &declaration)
		}
		_, hashErr := streamFile(ctx, path, fi, maxFileBytes, &budget, destination)
		if hashErr != nil {
			s.Complete = false
			f.Status = "HASH_ERROR"
			s.Files = append(s.Files, f)
			return fmt.Errorf("hash %s: %w", rel, hashErr)
		}
		f.SHA256 = hex.EncodeToString(h.Sum(nil))
		if emptyGoDeclarations(declaration.Bytes()) {
			f.GoModDeclaration = GoModNoDependenciesV1
		}
		s.Files = append(s.Files, f)
		return nil
	})
	if errors.Is(err, errEntryLimit) || errors.Is(err, stop) {
		s.Complete = false
	} else if err != nil {
		return Snapshot{}, err
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	sort.Strings(s.ReparsePaths)
	s.ManifestHash = manifestHash(s)
	// Snapshotting is deliberately non-executing. Git metadata is optional and
	// must not be obtained by resolving an executable from the caller's PATH.
	s.VCS = VCSState{System: "git", Dirty: "UNKNOWN", Status: "UNAVAILABLE"}
	s.TargetID = snapshotID(s)
	return s, nil
}

func manifestHash(s Snapshot) string {
	h := sha256.New()
	for _, f := range s.Files {
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s\n", f.Path, f.Size, f.SHA256, f.Status)
		if f.GoModDeclaration != "" {
			fmt.Fprintf(h, "go-mod-declaration\x00%s\x00%s\n", f.Path, f.GoModDeclaration)
		}
	}
	for _, p := range s.ReparsePaths {
		fmt.Fprintf(h, "reparse\x00%s\n", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func snapshotID(s Snapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s", s.ManifestHash, s.VCS.System, s.VCS.Commit, s.VCS.Dirty, s.VCS.Status)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// VerifySnapshotIdentity binds content-derived declarations to the confirmed
// target identity. Older snapshots without declarations retain their identities.
func VerifySnapshotIdentity(s Snapshot) bool {
	return s.ManifestHash == manifestHash(s) && s.TargetID == snapshotID(s)
}

func IsInside(root, candidate string) bool {
	r, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	c, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	r = filepath.Clean(r)
	c = filepath.Clean(c)
	if samePath(r, c) {
		return true
	}
	prefix := r + string(os.PathSeparator)
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(c), strings.ToLower(prefix))
	}
	return strings.HasPrefix(c, prefix)
}

func samePath(first, second string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}

// SafeRelative returns a portable target-relative path or rejects an absolute/traversing path.
func SafeRelative(root, candidate string) (string, error) {
	if !IsInside(root, candidate) {
		return "", fmt.Errorf("path escapes target root: %s", candidate)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve target root: %w", err)
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve candidate path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absCandidate)
	if err != nil || rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes target root: %s", candidate)
	}
	return filepath.ToSlash(rel), nil
}
