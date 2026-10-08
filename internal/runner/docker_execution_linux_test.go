//go:build linux

package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedDockerControlUsesFrozenNativeCLI(t *testing.T) {
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "docker-test-cli")
	approved := []byte("#!/bin/sh\nprintf 'APPROVED_CONTROL_PATH\\n'\n")
	if err := os.WriteFile(source, approved, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(approved)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	host := DockerHost{
		DockerPath: source, DockerSHA256: digest,
		SandboxPath: source, SandboxSHA256: digest,
		connection: func() (dockerConnection, error) {
			return dockerConnection{endpoint: "unix:///private-test-socket", user: "1000:1000"}, nil
		},
	}
	ctx := context.Background()
	if _, err := host.command(ctx, "image", "ls"); err == nil || !strings.Contains(err.Error(), "native executable pinning cannot exclude Unix writers") {
		t.Fatalf("unprepared native control path was not refused: %v", err)
	}
	if _, release, err := (DockerHost{DockerPath: source, DockerSHA256: "sha256:" + strings.Repeat("0", 64), SandboxPath: source, SandboxSHA256: digest}).prepareExecution(ctx, ExecutionSpec{TemporaryDir: filepath.Join(t.TempDir(), "scratch")}); err == nil || release != nil {
		t.Fatalf("incorrect native digest was accepted: %v", err)
	}
	publicParent := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(publicParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, release, err := host.prepareExecution(ctx, ExecutionSpec{TemporaryDir: filepath.Join(publicParent, "scratch")}); err == nil || release != nil {
		t.Fatalf("mutable frozen-input parent was accepted: %v", err)
	}

	prepared, release, err := host.prepareExecution(ctx, ExecutionSpec{TemporaryDir: filepath.Join(t.TempDir(), "scratch")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()
	frozen, ok := prepared.(DockerHost)
	if !ok || !frozen.preparedNative || frozen.DockerPath == source {
		t.Fatal("prepared Docker host did not retain a private CLI copy")
	}
	if err := os.Rename(sourceDir, sourceDir+"-previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("#!/bin/sh\nprintf 'REPLACED\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	output, err := frozen.command(ctx, "image", "ls")
	if err != nil || string(output) != "APPROVED_CONTROL_PATH\n" {
		t.Fatalf("native Docker control path did not use approved frozen bytes: %q %v", output, err)
	}
}
