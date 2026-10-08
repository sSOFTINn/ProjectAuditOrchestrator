package target

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureUsesSmallActualBudgetsAndSameDigest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := mustSnapshot(t, root)
	destination := filepath.Join(t.TempDir(), "capture")
	captured, err := CaptureWithBudgetContext(context.Background(), root, destination, expected, 3, 1, 3)
	if err != nil || !captured.Complete || captured.ManifestHash != expected.ManifestHash || captured.TargetID != expected.TargetID {
		t.Fatalf("bounded capture changed target identity: %#v %v", captured, err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "a.txt"))
	if err != nil || string(content) != "abc" {
		t.Fatalf("bounded copy mismatch: %q %v", content, err)
	}
}

func TestCaptureRejectsLimitsAndCancellationBeforeCreatingDestination(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := mustSnapshot(t, root)
	for _, tc := range []struct {
		name      string
		fileBytes int64
		total     int64
	}{{"file", 3, 4}, {"total", 4, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "capture")
			if _, err := CaptureWithBudgetContext(context.Background(), root, destination, expected, tc.fileBytes, 1, tc.total); err == nil {
				t.Fatal("capture exceeded budget")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("destination created for refused capture: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	destination := filepath.Join(t.TempDir(), "capture")
	if _, err := CaptureContext(ctx, root, destination, expected); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination created for canceled capture: %v", err)
	}
}

func TestCaptureRejectsDestinationInsideTarget(t *testing.T) {
	root := t.TempDir()
	expected := mustSnapshot(t, root)
	destination := filepath.Join(root, "capture")
	if _, err := Capture(root, destination, expected); err == nil {
		t.Fatal("overlap was accepted")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("overlapping destination was created: %v", err)
	}
}

func TestCaptureCreatesIndependentMatchingTree(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := Capture(root, filepath.Join(t.TempDir(), "capture"), expected)
	if err != nil || captured.ManifestHash != expected.ManifestHash {
		t.Fatalf("capture mismatch: %#v %v", captured, err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if captured.ManifestHash == mustSnapshot(t, root).ManifestHash {
		t.Fatal("capture changed with source")
	}
}

func mustSnapshot(t *testing.T, root string) Snapshot {
	t.Helper()
	s, err := SnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
