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
	source := filepath.Join(t.TempDir(), "docker-test")
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
	if p.SHA256 != digest || p.SourcePath != source {
		t.Fatal("prepared identity changed")
	}
	if runtime.GOOS == "windows" && p.Path != source {
		t.Fatal("Windows native DLL layout was changed")
	}
	if runtime.GOOS == "linux" && p.Path == source {
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
