package detect

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

type Result struct {
	Languages    []string `json:"languages"`
	Artifacts    []string `json:"artifacts"`
	Capabilities []string `json:"capabilities"`
	Indicators   []string `json:"indicators"`
	// These are expectations derived from file names, not a dependency inventory.
	ExpectedEcosystems []string          `json:"expected_ecosystems,omitempty"`
	DependencyInputs   []DependencyInput `json:"dependency_inputs,omitempty"`
}

// DependencyInput uses a closed vocabulary and excludes target paths. Scope is a
// file-name hint only; Detect never reads manifests or executes package managers.
type DependencyInput struct {
	Ecosystem string `json:"ecosystem"`
	Format    string `json:"format"`
	Scope     string `json:"scope"`
	Support   string `json:"support"`
}

const RecognizedFormat = "FORMAT_RECOGNIZED"
const UnsupportedFormat = "UNSUPPORTED_INPUT_FORMAT"

func KnownEcosystem(value string) bool {
	switch value {
	case "Go", "PyPI", "npm", "crates.io", "GitHubActions":
		return true
	}
	return false
}

func Detect(s target.Snapshot) Result {
	seenLang, seenArtifact, seenCapability, seenIndicator := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenInput, seenEcosystem := map[DependencyInput]bool{}, map[string]bool{}
	r := Result{}
	add := func(dst *[]string, seen map[string]bool, value string) {
		if !seen[value] {
			seen[value] = true
			*dst = append(*dst, value)
		}
	}
	for _, f := range s.Files {
		name := strings.ToLower(filepath.Base(filepath.FromSlash(f.Path)))
		path := strings.ToLower(f.Path)
		if input, ok := dependencyInput(name); ok {
			if !seenInput[input] {
				seenInput[input] = true
				r.DependencyInputs = append(r.DependencyInputs, input)
			}
			add(&r.ExpectedEcosystems, seenEcosystem, input.Ecosystem)
		}
		switch name {
		case "go.mod", "go.sum":
			add(&r.Languages, seenLang, "go")
			add(&r.Indicators, seenIndicator, "go-module-input")
		case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			add(&r.Languages, seenLang, "javascript")
		case "pyproject.toml", "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock", "requirements.lock", "build-requirements.lock":
			add(&r.Languages, seenLang, "python")
		case "cargo.toml", "cargo.lock":
			add(&r.Languages, seenLang, "rust")
		case "dockerfile":
			add(&r.Artifacts, seenArtifact, "container")
		case "terraform.lock.hcl":
			add(&r.Artifacts, seenArtifact, "terraform")
		}
		if strings.HasSuffix(name, ".tf") {
			add(&r.Artifacts, seenArtifact, "terraform")
		}
		if isWorkflowInput(path) {
			add(&r.Artifacts, seenArtifact, "github-actions")
			add(&r.Indicators, seenIndicator, "workflow-security-input")
		}
	}
	for _, capability := range []string{"inventory", "sbom"} {
		add(&r.Capabilities, seenCapability, capability)
	}
	if len(r.Artifacts) > 0 {
		add(&r.Capabilities, seenCapability, "infrastructure")
	}
	if seenIndicator["workflow-security-input"] {
		add(&r.Capabilities, seenCapability, "workflow-security")
	}
	sort.Strings(r.ExpectedEcosystems)
	sort.Slice(r.DependencyInputs, func(i, j int) bool {
		a, b := r.DependencyInputs[i], r.DependencyInputs[j]
		return a.Ecosystem+"\x00"+a.Format+"\x00"+a.Scope < b.Ecosystem+"\x00"+b.Format+"\x00"+b.Scope
	})
	return r
}

func dependencyInput(name string) (DependencyInput, bool) {
	input := DependencyInput{Format: name, Scope: "unspecified", Support: RecognizedFormat}
	switch name {
	case "go.mod", "go.sum":
		input.Ecosystem = "Go"
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		input.Ecosystem = "npm"
	case "pyproject.toml", "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock":
		input.Ecosystem = "PyPI"
	case "requirements.lock", "build-requirements.lock":
		// These names do not specify a wire format. Never silently treat a custom
		// .lock file as requirements.txt or claim that a scanner consumed it.
		input.Ecosystem, input.Support = "PyPI", UnsupportedFormat
		if name == "build-requirements.lock" {
			input.Scope = "build"
		}
	case "cargo.toml", "cargo.lock":
		input.Ecosystem = "crates.io"
	default:
		return DependencyInput{}, false
	}
	return input, true
}

// isWorkflowInput is path-only by design: PAO does not parse target configuration to plan zizmor.
func isWorkflowInput(path string) bool {
	path = strings.ToLower(strings.TrimPrefix(path, "./"))
	name := filepath.Base(filepath.FromSlash(path))
	if strings.HasPrefix(path, ".github/workflows/") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		return true
	}
	if name == "action.yml" || name == "action.yaml" || name == ".pre-commit-config.yml" || name == ".pre-commit-hooks.yml" {
		return true
	}
	return path == ".github/dependabot.yml" || path == ".github/dependabot.yaml"
}
