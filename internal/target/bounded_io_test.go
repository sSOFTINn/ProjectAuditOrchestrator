package target

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type reactingWriter struct {
	bytes.Buffer
	react func() error
}

func (w *reactingWriter) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if err == nil && w.react != nil {
		react := w.react
		w.react = nil
		err = react()
	}
	return n, err
}

func TestStreamFileGrowthCannotExceedActualByteBudgets(t *testing.T) {
	for _, limit := range []int64{8, 16} {
		t.Run(strconv.FormatInt(limit, 10), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "growing.bin")
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := lstatIdentity(path)
			if err != nil {
				t.Fatal(err)
			}
			budget := readBudget{remaining: limit}
			destination := &reactingWriter{react: func() error {
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				_, writeErr := file.WriteString("growth")
				closeErr := file.Close()
				return errors.Join(writeErr, closeErr)
			}}
			n, err := streamFile(context.Background(), path, initial, limit, &budget, destination)
			if err == nil || n != 8 || destination.Len() != 8 || budget.remaining != limit-8 {
				t.Fatalf("growth escaped bounds: bytes=%d written=%d remaining=%d error=%v", n, destination.Len(), budget.remaining, err)
			}
			current, statErr := os.Stat(path)
			if statErr != nil || current.Size() != 14 {
				t.Fatalf("growth fixture did not run: %v %v", current, statErr)
			}
		})
	}
}

func TestStreamFileReplacementWithIdenticalMetadataReadsNothing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source.bin")
	if err := os.WriteFile(path, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := lstatIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(root, "original.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, initial.ModTime(), initial.ModTime()); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Stat(path)
	if err != nil || replacement.Size() != initial.Size() || replacement.Mode() != initial.Mode() || !replacement.ModTime().Equal(initial.ModTime()) {
		t.Fatalf("replacement fixture metadata mismatch: %v %v", replacement, err)
	}
	budget := readBudget{remaining: 4}
	var destination bytes.Buffer
	n, err := streamFile(context.Background(), path, initial, 4, &budget, &destination)
	if err == nil || n != 0 || destination.Len() != 0 || budget.remaining != 4 {
		t.Fatalf("replacement identity was not rejected before I/O: %d %d %v", n, destination.Len(), err)
	}
}

func TestStreamFileSameSizeMutationDuringReadIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := lstatIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	destination := &reactingWriter{react: func() error {
		if err := os.WriteFile(path, []byte("modified"), 0o600); err != nil {
			return err
		}
		changedTime := initial.ModTime().Add(time.Second)
		return os.Chtimes(path, changedTime, changedTime)
	}}
	budget := readBudget{remaining: 8}
	n, err := streamFile(context.Background(), path, initial, 8, &budget, destination)
	if err == nil || n != 8 || destination.Len() != 8 || budget.remaining != 0 {
		t.Fatalf("same-size mutation was not detected with bounded I/O: %d %d %v", n, destination.Len(), err)
	}
}

type measuredReader struct {
	reader io.Reader
	bytes  int
	calls  int
}

func (r *measuredReader) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	r.bytes += n
	r.calls++
	return n, err
}

func TestBoundedCopyCancellationStopsBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	size := int64(copyBufferBytes + 8)
	source := &measuredReader{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, int(size)))}
	destination := &reactingWriter{react: func() error { cancel(); return nil }}
	budget := readBudget{remaining: size}
	n, err := copyExactly(ctx, destination, source, size, &budget)
	if !errors.Is(err, context.Canceled) || n != copyBufferBytes || source.bytes != copyBufferBytes || source.calls != 1 || destination.Len() != copyBufferBytes || budget.remaining != 8 {
		t.Fatalf("cancellation did not stop reads: n=%d bytes=%d calls=%d written=%d remaining=%d err=%v", n, source.bytes, source.calls, destination.Len(), budget.remaining, err)
	}
}

func TestStreamFileLimitsRejectBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := lstatIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		fileBytes int64
		total     int64
		want      error
	}{{"per-file", 3, 4, errFileLimit}, {"total", 4, 3, errTotalLimit}} {
		t.Run(tc.name, func(t *testing.T) {
			budget := readBudget{remaining: tc.total}
			var output bytes.Buffer
			n, err := streamFile(context.Background(), path, initial, tc.fileBytes, &budget, &output)
			if !errors.Is(err, tc.want) || n != 0 || output.Len() != 0 || budget.remaining != tc.total {
				t.Fatalf("limit did not stop before I/O: %d %v", n, err)
			}
		})
	}
}
