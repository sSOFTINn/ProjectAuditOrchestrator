package plan

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

func TestDryRunPlanPreservesTargetAndNeverStartsAvailableAdapter(t *testing.T) {
	targetRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetRoot, "go.mod"), []byte("module fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := target.SnapshotRoot(targetRoot)
	if err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	sentinel := filepath.Join(targetRoot, "adapter-was-started")
	adapterPath := filepath.Join(binDir, "trivy")
	if runtime.GOOS == "windows" {
		adapterPath += ".cmd"
		contents := "@echo off\r\necho started>\"" + sentinel + "\"\r\n"
		if err := os.WriteFile(adapterPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		contents := "#!/bin/sh\nprintf started > '" + sentinel + "'\n"
		if err := os.WriteFile(adapterPath, []byte(contents), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Keep ordinary host utilities (notably Git, which is recorded in the
	// immutable target identity) visible while placing the fake adapter first.
	// Replacing PATH altogether would change the observation environment rather
	// than exercising dry-run planning.
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	p := Build(before, "fast", true)
	if !p.DryRun {
		t.Fatal("expected dry-run plan")
	}
	if len(p.Nodes) != 2 || p.Nodes[1].ID != "trivy" || p.Nodes[1].Status != "AVAILABLE_NOT_STARTED" {
		t.Fatalf("expected available but not started trivy node: %#v", p.Nodes)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("dry-run plan started adapter or created sentinel: %v", err)
	}

	after, err := target.SnapshotRoot(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	if before.ManifestHash != after.ManifestHash || before.TargetID != after.TargetID {
		t.Fatalf("target changed during dry-run planning: before=%#v after=%#v", before, after)
	}
}
