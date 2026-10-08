package detect

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

func TestDetectUsesPathsOnly(t *testing.T) {
	s := target.Snapshot{Files: []target.FileEntry{{Path: "go.mod"}, {Path: "Dockerfile"}, {Path: ".github/workflows/ci.yml"}}}
	r := Detect(s)
	if len(r.Languages) != 1 || r.Languages[0] != "go" {
		t.Fatalf("languages: %#v", r.Languages)
	}
	if len(r.Artifacts) != 2 || len(r.Capabilities) != 4 || len(r.Indicators) != 2 || r.Indicators[0] != "go-module-input" || r.Indicators[1] != "workflow-security-input" {
		t.Fatalf("detected result: %#v", r)
	}
}

func TestDetectWorkflowInputsByPathWithoutReadingContent(t *testing.T) {
	for _, path := range []string{".github/dependabot.yaml", "action.yml", ".pre-commit-config.yml"} {
		result := Detect(target.Snapshot{Files: []target.FileEntry{{Path: path}}})
		if len(result.Indicators) != 1 || result.Indicators[0] != "workflow-security-input" {
			t.Fatalf("workflow indicator was not detected for %q: %#v", path, result)
		}
	}
	result := Detect(target.Snapshot{Files: []target.FileEntry{{Path: "README.md"}}})
	if len(result.Indicators) != 0 {
		t.Fatalf("unrelated file activated workflow security: %#v", result)
	}
}

func TestGoModuleDoesNotActivateWorkflowSecurity(t *testing.T) {
	result := Detect(target.Snapshot{Files: []target.FileEntry{{Path: "go.mod"}}})
	for _, capability := range result.Capabilities {
		if capability == "workflow-security" {
			t.Fatal("Go module was mistaken for workflow input")
		}
	}
}

func TestDependencyExpectationsAndCustomPythonLocks(t *testing.T) {
	result := Detect(target.Snapshot{Files: []target.FileEntry{
		{Path: "src/pyproject.toml"}, {Path: "requirements.lock"}, {Path: "build-requirements.lock"},
		{Path: "duplicate/requirements.lock"}, {Path: "unrelated.lock"}, {Path: "go.mod"},
	}})
	if len(result.ExpectedEcosystems) != 2 || result.ExpectedEcosystems[0] != "Go" || result.ExpectedEcosystems[1] != "PyPI" || len(result.DependencyInputs) != 4 {
		t.Fatalf("expectations: %+v", result)
	}
	for _, input := range result.DependencyInputs {
		switch input.Format {
		case "requirements.lock":
			if input.Support != UnsupportedFormat || input.Scope != "unspecified" {
				t.Fatal(input)
			}
		case "build-requirements.lock":
			if input.Support != UnsupportedFormat || input.Scope != "build" {
				t.Fatal(input)
			}
		case "go.mod", "pyproject.toml":
			if input.Support != RecognizedFormat {
				t.Fatal(input)
			}
		default:
			t.Fatalf("arbitrary lock filename treated as a dependency: %+v", input)
		}
	}
	if noDependencies := Detect(target.Snapshot{Files: []target.FileEntry{{Path: "README.md"}, {Path: "unrelated.lock"}}}); len(noDependencies.DependencyInputs) != 0 {
		t.Fatal(noDependencies)
	}
}
