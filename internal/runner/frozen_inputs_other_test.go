//go:build !windows

package runner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnixFrozenRelativeOpenRemainsAnchoredAfterAncestorSwap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "source")
	frozenWriteTestFile(t, filepath.Join(root, "file"), []byte("approved"), 0o600)
	outside := t.TempDir()
	frozenWriteTestFile(t, filepath.Join(outside, "file"), []byte("outside-marker"), 0o600)
	directory, cleanup, err := frozenOpenChain(root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := os.Rename(root, root+"-previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	file, err := frozenOpenRelative(directory, "file", filepath.Join(root, "file"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 32))
	if err != nil || string(content) != "approved" {
		t.Fatalf("anchored read was redirected: %q %v", content, err)
	}
}

func TestUnixFreezeInputsRejectsSymlinkAndFIFOWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"link", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			spec, limits, _ := frozenFixture(t)
			path := filepath.Join(spec.StatePath, "special")
			if kind == "link" {
				outside := filepath.Join(t.TempDir(), "outside")
				frozenWriteTestFile(t, outside, []byte("outside-marker"), 0o600)
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			} else if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits); err == nil || cleanup != nil {
				t.Fatalf("special source was admitted: %v", err)
			}
		})
	}
}

func TestUnixNativePinRefusesToClaimWriterExclusion(t *testing.T) {
	if cleanup, err := PinExecutable(context.Background(), "/synthetic/not-read", frozenTestDigest([]byte("synthetic"))); err == nil || cleanup != nil {
		t.Fatal("Unix advisory locking was presented as mandatory writer exclusion")
	}
}

func TestUnixFreezeExecutableRejectsMutablePrivateParent(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(t.TempDir(), "inert")
	digest := frozenWriteTestFile(t, path, []byte("approved"), 0o755)
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := FreezeExecutableIn(context.Background(), path, digest, parent); err == nil || cleanup != nil {
		t.Fatal("world-writable private parent was admitted")
	}
	created, err := filepath.Glob(filepath.Join(parent, ".pao-frozen-*"))
	if err != nil || len(created) != 0 {
		t.Fatalf("unsafe parent received copies: %v %v", created, err)
	}
}
