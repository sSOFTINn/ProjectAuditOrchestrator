package target

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Capture makes a private, reparse-free copy before an audit mounts a target.
// The caller retains it as protected evidence; it is never a live target mount.
func Capture(root, destination string, expected Snapshot) (Snapshot, error) {
	return CaptureContext(context.Background(), root, destination, expected)
}

func CaptureContext(ctx context.Context, root, destination string, expected Snapshot) (Snapshot, error) {
	return CaptureWithBudgetContext(ctx, root, destination, expected, DefaultMaxFileBytes, DefaultMaxEntries, DefaultMaxTotalBytes)
}

// CaptureWithBudgetContext bounds each verification pass and the copy itself.
// Failed captures remain as bounded partial evidence for the caller to handle.
func CaptureWithBudgetContext(ctx context.Context, root, destination string, expected Snapshot, maxFileBytes int64, maxEntries int, maxTotalBytes int64) (Snapshot, error) {
	before, err := SnapshotRootWithBudgetContext(ctx, root, maxFileBytes, maxEntries, maxTotalBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("verify target before capture: %w", err)
	}
	if !expected.Complete || !before.Complete || len(before.ReparsePaths) != 0 || before.TargetID != expected.TargetID {
		return Snapshot{}, errors.New("target changed or contains redirected entries before capture")
	}
	absRoot := filepath.FromSlash(before.Root)
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return Snapshot{}, err
	}
	if IsInside(absRoot, absDestination) || IsInside(absDestination, absRoot) {
		return Snapshot{}, errors.New("capture destination overlaps target")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := os.Mkdir(absDestination, 0o700); err != nil {
		return Snapshot{}, err
	}
	files := make(map[string]FileEntry, len(before.Files))
	for _, file := range before.Files {
		files[file.Path] = file
	}
	budget := readBudget{remaining: maxTotalBytes}
	err = walkBounded(ctx, absRoot, maxEntries, func(path string, entry fs.DirEntry, info os.FileInfo) error {
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		if entry.Name() == ".git" && entry.IsDir() {
			return fs.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 || isReparsePoint(path) {
			return errors.New("target changed to include a redirected entry during capture")
		}
		out := filepath.Join(absDestination, rel)
		if entry.IsDir() {
			return os.Mkdir(out, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		confirmed, present := files[filepath.ToSlash(rel)]
		if !present || confirmed.Size != info.Size() {
			return errors.New("target file changed during capture")
		}
		if info.Size() > maxFileBytes {
			return errFileLimit
		}
		if info.Size() > budget.remaining {
			return errTotalLimit
		}
		output, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := streamFile(ctx, path, info, maxFileBytes, &budget, io.MultiWriter(output, hash))
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != confirmed.SHA256 {
			return errors.New("target content changed during capture")
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("capture target: %w", err)
	}
	after, err := SnapshotRootWithBudgetContext(ctx, absRoot, maxFileBytes, maxEntries, maxTotalBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("verify target after capture: %w", err)
	}
	if !after.Complete || len(after.ReparsePaths) != 0 || after.TargetID != expected.TargetID {
		return Snapshot{}, errors.New("target changed during capture")
	}
	captured, err := SnapshotRootWithBudgetContext(ctx, absDestination, maxFileBytes, maxEntries, maxTotalBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("verify captured target: %w", err)
	}
	if !captured.Complete || len(captured.ReparsePaths) != 0 || captured.ManifestHash != expected.ManifestHash {
		return Snapshot{}, errors.New("captured target does not match the confirmed target")
	}
	return captured, nil
}
