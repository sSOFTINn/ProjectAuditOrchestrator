package target

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// walkBounded limits all non-root entries, including directories and redirected
// entries. ReadDir is incremental: at most the remaining entry budget plus one
// overflow sentinel is retained, rather than an unbounded directory listing.
func walkBounded(ctx context.Context, root string, maxEntries int, visit func(string, fs.DirEntry, os.FileInfo) error) error {
	info, err := lstatIdentity(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(root) {
		return errors.New("target root is not an unredirected directory")
	}
	remaining := maxEntries
	var walk func(string, os.FileInfo) error
	walk = func(path string, expected os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil || !current.IsDir() || isReparsePoint(path) || !os.SameFile(expected, current) || expected.Mode() != current.Mode() {
			return errors.New("target directory changed before enumeration")
		}
		// Windows directory entries may carry cached timestamps. Establish a
		// fresh path-stat baseline while retaining the enumerated identity.
		expected = current
		directory, err := openTargetEntry(path, true)
		if err != nil {
			return err
		}
		defer directory.Close()
		opened, err := directory.Stat()
		if err != nil || !unchangedFile(expected, opened) {
			return errors.New("target directory changed before enumeration")
		}
		var entries []fs.DirEntry
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			chunkSize := 256
			if remaining < chunkSize {
				chunkSize = remaining + 1
			}
			chunk, readErr := directory.ReadDir(chunkSize)
			if len(chunk) > remaining {
				return errEntryLimit
			}
			remaining -= len(chunk)
			entries = append(entries, chunk...)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			current, err := os.Lstat(path)
			if err != nil || isReparsePoint(path) || !unchangedFile(expected, current) {
				return errors.New("target directory changed during enumeration")
			}
			child := filepath.Join(path, entry.Name())
			enumerated, err := entry.Info()
			if err != nil {
				return err
			}
			info, err := lstatIdentity(child)
			if err != nil || !os.SameFile(enumerated, info) || enumerated.Mode() != info.Mode() {
				return errors.New("target entry identity changed during enumeration")
			}
			if err := visit(child, entry, info); err != nil {
				if err == fs.SkipDir && entry.IsDir() {
					continue
				}
				return err
			}
			if entry.IsDir() {
				if err := walk(child, info); err != nil {
					return err
				}
			}
		}
		finished, err := directory.Stat()
		if err != nil || !unchangedFile(expected, finished) {
			return errors.New("target directory changed during enumeration")
		}
		current, err = os.Lstat(path)
		if err != nil || isReparsePoint(path) || !unchangedFile(expected, current) {
			return errors.New("target directory changed during enumeration")
		}
		return nil
	}
	return walk(root, info)
}
