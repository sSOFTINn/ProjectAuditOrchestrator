package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

func TestPreparedCLIGenerationIsVerifiedAndReusable(t *testing.T) {
	state, err := installation.Initialize(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	// Preserve a lexical alias: hosted Windows TEMP may likewise use an 8.3
	// alias, while preparation records the canonical path to the same file.
	source := t.TempDir() + string(os.PathSeparator) + "." + string(os.PathSeparator) + "docker-test"
	bytes := []byte("synthetic approved CLI bytes")
	if err := os.WriteFile(source, bytes, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bytes)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	p, err := PrepareDockerCLI(context.Background(), source, digest, state.Root())
	if err != nil {
		t.Fatal(err)
	}
	if p.SHA256 != digest {
		t.Fatal("prepared digest changed")
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	preparedSourceInfo, err := os.Stat(p.SourcePath)
	if err != nil || !os.SameFile(sourceInfo, preparedSourceInfo) {
		t.Fatalf("prepared source identifies a different file: %q -> %q: %v", source, p.SourcePath, err)
	}
	if !filepath.IsAbs(p.SourcePath) {
		t.Fatal("prepared source path is not absolute")
	}
	if runtime.GOOS == "windows" && p.Path != p.SourcePath {
		t.Fatal("Windows native DLL layout was changed")
	}
	if runtime.GOOS == "linux" && p.Path == p.SourcePath {
		t.Fatal("Linux CLI was not privately copied")
	}
	again, err := PrepareDockerCLI(context.Background(), source, digest, state.Root())
	if err != nil || again != p {
		t.Fatalf("verified generation could not resume: %v", err)
	}
	if _, err := readPreparedCLI(state.Root(), digest); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		if err := os.Chmod(p.Path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.Path, []byte("changed CLI"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readPreparedCLI(state.Root(), digest); err == nil {
		t.Fatal("tampered prepared CLI accepted")
	}
}
