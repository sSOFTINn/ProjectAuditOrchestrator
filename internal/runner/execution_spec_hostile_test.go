package runner

import (
	"path/filepath"
	"testing"
)

func TestExecutionSpecRejectsShellAndNulArgumentInjection(t *testing.T) {
	root := t.TempDir()
	spec := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "fixture", ToolID: "fixture", ToolPath: filepath.Join(root, "cmd.exe"), Arguments: []string{"/c", "untrusted"}, TargetRoot: root, TemporaryDir: t.TempDir(), TimeoutSeconds: 60, Sandbox: strongSandbox()}
	if err := spec.Validate(); err == nil {
		t.Fatal("shell execution request was accepted")
	}
	spec.ToolPath = filepath.Join(root, "fixture-tool")
	spec.Arguments = []string{"scan\x00injected"}
	if err := spec.Validate(); err == nil {
		t.Fatal("NUL argument injection was accepted")
	}
}
