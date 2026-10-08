package runner

import (
	"path/filepath"
	"testing"
)

func strongSandbox() SandboxProperties {
	return SandboxProperties{Isolation: StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}
}

func TestExecutionSpecRequiresAllStrongIsolationProperties(t *testing.T) {
	root := t.TempDir()
	spec := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "fixture", ToolID: "fixture", ToolPath: filepath.Join(root, "tool"), Arguments: []string{"scan", root}, TargetRoot: root, TemporaryDir: t.TempDir(), TimeoutSeconds: 60, Sandbox: strongSandbox()}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.Sandbox.Isolation = "native"
	if err := spec.Validate(); err == nil {
		t.Fatal("native process mode was accepted for scanner execution")
	}
	spec.Sandbox = strongSandbox()
	spec.TemporaryDir = filepath.Join(root, "output")
	if err := spec.Validate(); err == nil {
		t.Fatal("target-local temporary directory was accepted")
	}
	spec.TemporaryDir = t.TempDir()
	spec.StatePath = t.TempDir()
	if err := spec.Validate(); err == nil {
		t.Fatal("prepared state without digest was accepted")
	}
	spec.StateDigest = recordDigest
	spec.StatePath = filepath.Join(root, "state")
	if err := spec.Validate(); err == nil {
		t.Fatal("target-local prepared state was accepted")
	}
	spec.StatePath = t.TempDir()
	spec.StateEntrypoint = "scancode-toolkit/venv/bin/scancode"
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid prepared-state entrypoint rejected: %v", err)
	}
	spec.StateEntrypoint = "../tool"
	if err := spec.Validate(); err == nil {
		t.Fatal("prepared-state parent traversal was accepted")
	}
	spec.StateEntrypoint = "/bin/sh"
	if err := spec.Validate(); err == nil {
		t.Fatal("absolute prepared-state entrypoint was accepted")
	}
	spec.StateEntrypoint = ""
	spec.RulePackPath = t.TempDir()
	if err := spec.Validate(); err == nil {
		t.Fatal("rule pack without digest was accepted")
	}
	spec.RulePackDigest = recordDigest
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid rule-pack declaration rejected: %v", err)
	}
	spec.RuntimeDigest = "mutable:latest"
	if err := spec.Validate(); err == nil {
		t.Fatal("mutable runtime identity was accepted")
	}
	spec.RuntimeDigest = recordDigest
	spec.LicenseDataDigest = recordDigest
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid production prerequisite digests rejected: %v", err)
	}
	spec.OutputFile = "scancode.json"
	if err := spec.Validate(); err == nil {
		t.Fatal("output file without media type was accepted")
	}
	spec.OutputMediaType = "application/json"
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid output-file declaration rejected: %v", err)
	}
	spec.OutputFile = "../outside.json"
	if err := spec.Validate(); err == nil {
		t.Fatal("output-file path traversal was accepted")
	}
	spec.OutputFile = ""
	spec.OutputMediaType = ""
	spec.MemoryMB = 2048
	spec.ContainerName = "pao-fixture-r2"
	if err := spec.Validate(); err != nil {
		t.Fatalf("valid resource controls rejected: %v", err)
	}
	spec.MemoryMB = 8192
	if err := spec.Validate(); err == nil {
		t.Fatal("unbounded memory limit was accepted")
	}
}
