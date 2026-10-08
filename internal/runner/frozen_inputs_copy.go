package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
)

const frozenCopyBufferBytes = 32 << 10

type frozenFile struct {
	digest string
	size   int64
}

func frozenIdentity(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, info) {
		return nil, errors.New("cannot pin frozen-input identity")
	}
	return info, nil
}

func frozenUnchanged(expected, observed os.FileInfo) bool {
	return os.SameFile(expected, observed) && expected.Size() == observed.Size() &&
		expected.Mode() == observed.Mode() && expected.ModTime().Equal(observed.ModTime())
}

// Open every source ancestor, keeping its identity stable until the returned
// cleanup runs. Unix children use openat on held parent descriptors; Windows
// handles deny writes/deletion and open the reparse entry itself.
func frozenOpenChain(path string, directory bool) (*os.File, func(), error) {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return nil, nil, err
	}
	volume := filepath.VolumeName(path)
	root := volume + string(os.PathSeparator)
	current, err := frozenOpenPath(root, true)
	if err != nil {
		return nil, nil, err
	}
	opened := []*os.File{current}
	cleanup := func() {
		for index := len(opened) - 1; index >= 0; index-- {
			_ = opened[index].Close()
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, root), string(os.PathSeparator))
	if len(parts) == 1 && parts[0] == "" {
		if !directory {
			cleanup()
			return nil, nil, errors.New("source file cannot be a filesystem root")
		}
		return current, cleanup, nil
	}
	currentPath := root
	for index, part := range parts {
		currentPath = filepath.Join(currentPath, part)
		isDirectory := index < len(parts)-1 || directory
		child, err := frozenOpenRelative(current, part, currentPath, isDirectory)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		opened = append(opened, child)
		info, err := child.Stat()
		if err != nil || (isDirectory && !info.IsDir()) || (!isDirectory && !info.Mode().IsRegular()) {
			cleanup()
			return nil, nil, errors.New("source chain contains a redirected or nonregular entry")
		}
		current = child
	}
	return current, cleanup, nil
}

func (s *frozenSession) countEntry() error {
	if s.entries >= s.limits.MaxEntries {
		return errors.New("frozen inputs exceed entry limit")
	}
	s.entries++
	return nil
}

func (s *frozenSession) makeDirectory(path string) error {
	if err := s.countEntry(); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	s.ownedPaths = append(s.ownedPaths, path)
	return nil
}

func (s *frozenSession) copyFile(ctx context.Context, parent *os.File, sourcePath, destination string) (frozenFile, error) {
	if err := ctx.Err(); err != nil {
		return frozenFile{}, err
	}
	if err := s.countEntry(); err != nil {
		return frozenFile{}, err
	}
	var source *os.File
	if parent == nil {
		if s.examined >= s.limits.MaxEntries {
			return frozenFile{}, errors.New("frozen inputs exceed enumerated entry limit")
		}
		s.examined++
		opened, cleanup, err := frozenOpenChain(sourcePath, false)
		if err != nil {
			return frozenFile{}, err
		}
		source = opened
		defer cleanup()
	} else {
		opened, err := frozenOpenRelative(parent, filepath.Base(sourcePath), sourcePath, false)
		if err != nil {
			return frozenFile{}, err
		}
		source = opened
		defer source.Close()
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return frozenFile{}, errors.New("frozen source must be a regular file")
	}
	if info.Size() > s.limits.MaxFileBytes || info.Size() > s.limits.MaxTotalBytes-s.written {
		return frozenFile{}, errors.New("frozen inputs exceed file or total byte limit")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return frozenFile{}, err
	}
	s.ownedPaths = append(s.ownedPaths, destination)
	hash := sha256.New()
	copyErr := s.copyExactly(ctx, io.MultiWriter(output, hash), source, info.Size(), true)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return frozenFile{}, errors.Join(copyErr, closeErr)
	}
	finished, err := source.Stat()
	pathInfo, pathErr := os.Lstat(sourcePath)
	if err != nil || pathErr != nil || !frozenUnchanged(info, finished) || !frozenUnchanged(info, pathInfo) || auditconfig.CheckPath(sourcePath, false) != nil {
		return frozenFile{}, errors.New("frozen source changed during copying")
	}
	// Release source locks before the test barrier or a cooperating updater.
	// Deferred closing remains harmless; held ancestor handles are released on return.
	if err := source.Close(); err != nil {
		return frozenFile{}, err
	}
	if s.afterCopy != nil {
		if err := s.afterCopy(sourcePath, destination); err != nil {
			return frozenFile{}, err
		}
	}
	readback, err := frozenOpenPath(destination, false)
	if err != nil {
		return frozenFile{}, err
	}
	readbackHash := sha256.New()
	readbackErr := s.copyExactly(ctx, readbackHash, readback, info.Size(), false)
	readbackInfo, statErr := readback.Stat()
	readbackCloseErr := readback.Close()
	if readbackErr != nil || statErr != nil || readbackCloseErr != nil || readbackInfo.Size() != info.Size() || !bytes.Equal(hash.Sum(nil), readbackHash.Sum(nil)) {
		return frozenFile{}, errors.Join(readbackErr, statErr, readbackCloseErr, errors.New("frozen copy readback mismatch"))
	}
	mode := os.FileMode(0o444) | info.Mode().Perm()&0o111
	if err := os.Chmod(destination, mode); err != nil {
		return frozenFile{}, err
	}
	return frozenFile{digest: "sha256:" + hex.EncodeToString(readbackHash.Sum(nil)), size: info.Size()}, nil
}

func (s *frozenSession) copyExactly(ctx context.Context, destination io.Writer, source io.Reader, size int64, payload bool) error {
	if size < 0 || size > 3*s.limits.MaxTotalBytes-s.read || (payload && size > s.limits.MaxTotalBytes-s.written) {
		return errors.New("frozen inputs exceed actual I/O budget")
	}
	bufferBytes := int64(frozenCopyBufferBytes)
	if size < bufferBytes {
		bufferBytes = size
	}
	buffer := make([]byte, int(bufferBytes))
	var consumed int64
	for consumed < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		readBytes := int64(len(buffer))
		if size-consumed < readBytes {
			readBytes = size - consumed
		}
		n, readErr := source.Read(buffer[:int(readBytes)])
		if n < 0 || n > int(readBytes) {
			return errors.New("invalid frozen input read count")
		}
		consumed += int64(n)
		s.read += int64(n)
		if err := ctx.Err(); err != nil {
			return err
		}
		if n > 0 {
			written, writeErr := destination.Write(buffer[:n])
			if payload {
				s.written += int64(written)
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF && consumed == size {
				break
			}
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return ctx.Err()
}

func (s *frozenSession) copyTree(ctx context.Context, root, destination string) (map[string]frozenFile, error) {
	if s.examined >= s.limits.MaxEntries {
		return nil, errors.New("frozen inputs exceed enumerated entry limit")
	}
	s.examined++
	source, closeSource, err := frozenOpenChain(root, true)
	if err != nil {
		return nil, err
	}
	defer closeSource()
	if err := s.makeDirectory(destination); err != nil {
		return nil, err
	}
	observed := map[string]frozenFile{}
	var walk func(*os.File, string, string, string) error
	walk = func(directory *os.File, path, out, relative string) error {
		baseline, err := directory.Stat()
		if err != nil || !baseline.IsDir() {
			return errors.New("frozen source is not a regular directory")
		}
		var entries []os.DirEntry
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			remaining := s.limits.MaxEntries - s.examined
			chunkSize := min(256, remaining+1)
			chunk, readErr := directory.ReadDir(chunkSize)
			if len(chunk) > remaining {
				return errors.New("frozen inputs exceed entry limit")
			}
			s.examined += len(chunk)
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
			child, childOut := filepath.Join(path, entry.Name()), filepath.Join(out, entry.Name())
			childRel := filepath.ToSlash(filepath.Join(relative, entry.Name()))
			if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
				return errors.New("frozen input trees cannot contain links or special files")
			}
			if entry.IsDir() {
				opened, err := frozenOpenRelative(directory, entry.Name(), child, true)
				if err != nil {
					return err
				}
				mkdirErr := s.makeDirectory(childOut)
				if mkdirErr == nil {
					mkdirErr = walk(opened, child, childOut, childRel)
				}
				closeErr := opened.Close()
				if mkdirErr != nil || closeErr != nil {
					return errors.Join(mkdirErr, closeErr)
				}
				continue
			}
			file, err := s.copyFile(ctx, directory, child, childOut)
			if err != nil {
				return fmt.Errorf("copy frozen input %s: %w", childRel, err)
			}
			observed[childRel] = file
		}
		finished, err := directory.Stat()
		pathInfo, pathErr := os.Lstat(path)
		if err != nil || pathErr != nil || !frozenUnchanged(baseline, finished) || !frozenUnchanged(baseline, pathInfo) || auditconfig.CheckPath(path, false) != nil {
			return errors.New("frozen input directory changed during copying")
		}
		return nil
	}
	if err := walk(source, root, destination, ""); err != nil {
		return nil, err
	}
	return observed, nil
}

func (s *frozenSession) seal(ctx context.Context) error {
	// The private base stays 0700. Readonly descendants can be mounted directly
	// for the non-root VM user without granting host users traversal of the base.
	for _, path := range s.ownedPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := os.Chmod(path, 0o555); err != nil {
				return err
			}
		}
		locked, err := frozenHoldPrivate(path, info.IsDir())
		if err != nil {
			return err
		}
		if locked != nil {
			s.handles = append(s.handles, locked)
		}
	}
	return ctx.Err()
}
