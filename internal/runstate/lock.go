// Package runstate owns crash-safe, resumable PAO run directories.
package runstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
)

const lockName = "plan.lock.json"

type Store struct{ root string }

type Run struct {
	Directory string    `json:"directory"`
	LockPath  string    `json:"lock_path"`
	Plan      plan.Plan `json:"plan"`
}

func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("run-state root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve run-state root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create run-state root: %w", err)
	}
	if err := realDirectory(abs); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

// Create creates or verifies the digest-named run directory. The lock is written
// to a synced temporary file and then atomically published; a crash can leave only
// an ignored temporary file, never a partially trusted lock.
func (s *Store) Create(p plan.Plan) (Run, error) {
	if s == nil || s.root == "" {
		return Run{}, errors.New("run-state store is not open")
	}
	if err := plan.Verify(p); err != nil {
		return Run{}, err
	}
	digest := strings.TrimPrefix(p.PlanDigest, "sha256:")
	if len(digest) != 64 || strings.ContainsAny(digest, `/\\`) {
		return Run{}, errors.New("unsafe plan digest")
	}
	directory := filepath.Join(s.root, digest)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Run{}, fmt.Errorf("create run directory: %w", err)
	}
	if err := realDirectory(directory); err != nil {
		return Run{}, err
	}
	lockPath := filepath.Join(directory, lockName)
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Run{}, errors.New("plan lock is not a regular file")
		}
		return s.Resume(p.PlanDigest)
	} else if !os.IsNotExist(err) {
		return Run{}, fmt.Errorf("inspect plan lock: %w", err)
	}
	canonical, err := plan.LockJSON(p)
	if err != nil {
		return Run{}, err
	}
	temp, err := os.CreateTemp(directory, ".plan-lock-*")
	if err != nil {
		return Run{}, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return Run{}, err
	}
	if _, err := temp.Write(canonical); err != nil {
		temp.Close()
		return Run{}, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return Run{}, err
	}
	if err := temp.Close(); err != nil {
		return Run{}, err
	}
	if err := os.Rename(tempPath, lockPath); err != nil {
		if os.IsExist(err) {
			return s.Resume(p.PlanDigest)
		}
		return Run{}, fmt.Errorf("publish plan lock: %w", err)
	}
	if err := os.Chmod(lockPath, 0o400); err != nil {
		return Run{}, fmt.Errorf("protect plan lock: %w", err)
	}
	return Run{Directory: directory, LockPath: lockPath, Plan: p}, nil
}

// Resume re-reads and verifies an already published lock, without mutating it.
func (s *Store) Resume(planDigest string) (Run, error) {
	if s == nil || s.root == "" {
		return Run{}, errors.New("run-state store is not open")
	}
	digest := strings.TrimPrefix(planDigest, "sha256:")
	if len(digest) != 64 || strings.ContainsAny(digest, `/\\`) {
		return Run{}, errors.New("unsafe plan digest")
	}
	directory := filepath.Join(s.root, digest)
	if err := realDirectory(directory); err != nil {
		return Run{}, err
	}
	lockPath := filepath.Join(directory, lockName)
	info, err := os.Lstat(lockPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Run{}, errors.New("verified plan lock is unavailable")
	}
	contents, err := os.ReadFile(lockPath)
	if err != nil {
		return Run{}, err
	}
	var locked plan.Plan
	if err := json.Unmarshal(contents, &locked); err != nil {
		return Run{}, fmt.Errorf("decode plan lock: %w", err)
	}
	if locked.PlanDigest != planDigest || plan.Verify(locked) != nil {
		return Run{}, errors.New("plan lock digest verification failed")
	}
	canonical, err := plan.LockJSON(locked)
	if err != nil || string(canonical) != string(contents) {
		return Run{}, errors.New("plan lock is not canonical")
	}
	return Run{Directory: directory, LockPath: lockPath, Plan: locked}, nil
}

func realDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("run-state path must be a real directory")
	}
	return nil
}
