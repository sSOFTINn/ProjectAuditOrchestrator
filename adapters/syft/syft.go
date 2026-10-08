// Package syft implements the data contract for the first approved SBOM adapter vertical slice.
package syft

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

const ID = "syft"

func Manifest() adapter.Manifest {
	return adapter.Manifest{
		APIVersion:         adapter.ManifestVersion,
		ID:                 ID,
		DisplayName:        "Syft SBOM inventory",
		Upstream:           "https://github.com/anchore/syft",
		Capabilities:       []string{"inventory", "sbom"},
		SupportedPlatforms: []string{"windows-amd64", "linux-amd64", "linux-arm64"},
		InputKinds:         []string{"directory"},
		OutputKinds:        []string{"syft-json"},
		SourceLicense:      "Apache-2.0",
		Redistribution:     "user-installed-only",
		Network:            "never-during-audit",
		TimeoutSeconds:     900,
		ParserSchema:       "syft-json/v1",
		FixedArguments:     []string{"scan", "dir:${target}", "--output", "json=${output}", "--output", "cyclonedx-json=${additional_output_0}"},
		RequiredSandbox:    []string{"container-vm", "repository-read-only", "temporary-write-only", "network-denied", "environment-sanitized", "process-tree-controlled", "cpu-limited", "memory-limited", "filesystem-isolated", "clean-runtime"},
		PrerequisiteKinds:  []string{"tool", "config"},
		FixtureCases:       []string{"success", "empty", "partial", "error", "malformed"},
		MaxOutputBytes:     64 << 20,
		RedactionClass:     "standard",
		Limitations:        []string{"does-not-assess-vulnerabilities"},
	}
}

type Result struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	SchemaVersion  string `json:"schema_version,omitempty"`
	ComponentCount int    `json:"component_count"`
}

// Parse is deliberately narrow: it establishes whether an output is a usable Syft JSON SBOM,
// not whether dependencies are safe. Normalization is owned by the trusted core in a later phase.
func Parse(raw []byte) Result {
	var document struct {
		Schema struct {
			Version string `json:"version"`
		} `json:"schema"`
		Artifacts  []json.RawMessage `json:"artifacts"`
		Error      string            `json:"error"`
		Status     string            `json:"status"`
		Descriptor struct {
			Configuration struct {
				Notes []string `json:"notes"`
			} `json:"configuration"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return Result{Status: "FAILED", Reason: "malformed Syft JSON"}
	}
	if document.Error != "" || document.Status == "FAILED" {
		return Result{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if document.Schema.Version == "" {
		return Result{Status: "FAILED", Reason: "missing Syft schema version"}
	}
	result := Result{SchemaVersion: document.Schema.Version, ComponentCount: len(document.Artifacts)}
	if len(document.Descriptor.Configuration.Notes) > 0 {
		result.Status = "PARTIAL"
		result.Reason = strings.Join(document.Descriptor.Configuration.Notes, "; ")
		return result
	}
	if result.ComponentCount == 0 {
		result.Status = "NO_FINDINGS"
		return result
	}
	result.Status = "SUCCEEDED"
	return result
}

// Ingest persists native bytes first, including malformed or failed outputs, then records the
// parser status. The raw reference is available for a future corrected parser to reprocess.
func Ingest(store *artifact.Store, raw []byte, executionID string) (artifact.RawArtifact, Result, error) {
	rawArtifact, err := store.PutRaw("application/vnd.syft+json", raw, executionID)
	if err != nil {
		return artifact.RawArtifact{}, Result{}, err
	}
	result := Parse(raw)
	if err := store.Append(artifact.Event{Type: "SYFT_OUTPUT_PARSED", ExecutionID: executionID, Artifact: rawArtifact.SHA256, Status: result.Status}); err != nil {
		return artifact.RawArtifact{}, Result{}, err
	}
	return rawArtifact, result, nil
}

// ExecutionSpec creates only a validated data request. A future host runner may launch it only
// after it establishes the required container/VM isolation; this adapter never launches Syft.
func ExecutionSpec(toolPath, targetRoot, temporaryDir string) runner.ExecutionSpec {
	return runner.ExecutionSpec{
		APIVersion:        "pao.dev/execution/v1alpha1",
		AdapterID:         ID,
		ToolID:            ID,
		ToolPath:          toolPath,
		Arguments:         []string{"scan", "dir:" + targetRoot, "--output", "json=" + filepath.Join(temporaryDir, "syft.json"), "--output", "cyclonedx-json=" + filepath.Join(temporaryDir, "syft.cdx.json")},
		AdditionalOutputs: []runner.DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}},
		TargetRoot:        targetRoot,
		TemporaryDir:      temporaryDir,
		Environment:       map[string]string{},
		TimeoutSeconds:    900,
		Sandbox: runner.SandboxProperties{
			Isolation:             runner.StrongIsolation,
			RepositoryReadOnly:    true,
			TemporaryWriteOnly:    true,
			NetworkDenied:         true,
			EnvironmentSanitized:  true,
			ProcessTreeControlled: true,
			CPULimited:            true,
			MemoryLimited:         true,
			FilesystemIsolated:    true,
			CleanRuntime:          true,
		},
	}
}
