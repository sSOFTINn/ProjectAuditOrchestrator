package target

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	errFileLimit  = errors.New("target file exceeds byte limit")
	errTotalLimit = errors.New("target exceeds total byte limit")
	errEntryLimit = errors.New("target exceeds entry limit")
)

const copyBufferBytes = 32 << 10

// readBudget measures bytes actually read, including reads whose writes fail.
type readBudget struct {
	remaining int64
}

func lstatIdentity(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	// On Windows Lstat's file ID is lazy. Resolve it before saving a baseline,
	// so a later path replacement cannot change the baseline's identity.
	if !os.SameFile(info, info) {
		return nil, errors.New("cannot establish target entry identity")
	}
	return info, nil
}

func unchangedFile(expected, actual os.FileInfo) bool {
	return os.SameFile(expected, actual) && expected.Mode() == actual.Mode() &&
		expected.Size() == actual.Size() && expected.ModTime().Equal(actual.ModTime())
}

func checkFilePath(path string, expected os.FileInfo) error {
	actual, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !actual.Mode().IsRegular() || isReparsePoint(path) || !unchangedFile(expected, actual) {
		return errors.New("target file identity or metadata changed")
	}
	return nil
}

// streamFile never reads beyond the initial size, per-file limit, or remaining
// total budget. A growing file is rejected by the metadata checks without an
// extra probe byte. File and path identities are checked on both sides of I/O.
func streamFile(ctx context.Context, path string, expected os.FileInfo, maxFileBytes int64, budget *readBudget, destination io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !expected.Mode().IsRegular() || expected.Size() < 0 {
		return 0, errors.New("target entry is not a regular file")
	}
	if expected.Size() > maxFileBytes {
		return 0, errFileLimit
	}
	if expected.Size() > budget.remaining {
		return 0, errTotalLimit
	}
	if err := checkFilePath(path, expected); err != nil {
		return 0, err
	}
	source, err := openTargetEntry(path, false)
	if err != nil {
		return 0, err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !unchangedFile(expected, opened) || !opened.Mode().IsRegular() {
		return 0, errors.New("target file changed before reading")
	}
	// Recheck the path after opening, before consuming any content.
	if err := checkFilePath(path, expected); err != nil {
		return 0, err
	}
	n, err := copyExactly(ctx, destination, source, expected.Size(), budget)
	if err != nil {
		return n, err
	}
	finished, err := source.Stat()
	if err != nil || !unchangedFile(expected, finished) {
		return n, errors.New("target file changed while reading")
	}
	if err := checkFilePath(path, expected); err != nil {
		return n, err
	}
	return n, nil
}

func copyExactly(ctx context.Context, destination io.Writer, source io.Reader, size int64, budget *readBudget) (int64, error) {
	if size < 0 || size > budget.remaining {
		return 0, errTotalLimit
	}
	bufferSize := int64(copyBufferBytes)
	if size < bufferSize {
		bufferSize = size
	}
	buffer := make([]byte, int(bufferSize))
	var consumed int64
	for consumed < size {
		if err := ctx.Err(); err != nil {
			return consumed, err
		}
		readSize := int64(len(buffer))
		if size-consumed < readSize {
			readSize = size - consumed
		}
		n, readErr := source.Read(buffer[:int(readSize)])
		if n < 0 || n > int(readSize) {
			return consumed, errors.New("invalid target read count")
		}
		consumed += int64(n)
		budget.remaining -= int64(n)
		if err := ctx.Err(); err != nil {
			return consumed, err
		}
		if n > 0 {
			written, writeErr := destination.Write(buffer[:n])
			if writeErr != nil {
				return consumed, writeErr
			}
			if written != n {
				return consumed, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF && consumed == size {
				break
			}
			return consumed, fmt.Errorf("read target: %w", readErr)
		}
		if n == 0 {
			return consumed, io.ErrNoProgress
		}
	}
	return consumed, ctx.Err()
}
