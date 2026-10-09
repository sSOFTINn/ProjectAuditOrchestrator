package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestOpengrepProductionCandidateThroughHostRunner(t *testing.T) {
	requireProductionCandidateIntegration(t)
	toolPath := requiredEnvironment(t, "PAO_OPENGREP_TOOL_PATH")
	statePath := requiredEnvironment(t, "PAO_OPENGREP_STATE_PATH")
	rulePath := requiredEnvironment(t, "PAO_OPENGREP_RULE_PATH")
	targetPath := requiredEnvironment(t, "PAO_OPENGREP_TARGET_PATH")
	runtimeDigest := requiredEnvironment(t, "PAO_OPENGREP_RUNTIME_DIGEST")
	stateDigest := fileDigestReference(t, filepath.Join(statePath, preparedStateManifestName))
	ruleDigest := fileDigestReference(t, filepath.Join(rulePath, inputCapsuleManifestName))
	now := time.Now().UTC()
	registry, err := toolchain.New([]toolchain.Record{{
		ID: "opengrep", Version: "1.29.0", SHA256: fileDigestHex(t, toolPath), SourceLicense: "LGPL-2.1-only", Redistribution: "user-installed-only",
		StateSHA256: stateDigest[len("sha256:"):], RuntimeSHA256: runtimeDigest[len("sha256:"):], RulePackSHA256: ruleDigest[len("sha256:"):],
		StateAt: now, RuntimeAt: now, RulePackAt: now,
		StateEnvironment: map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := loadProductionManifest(t, "opengrep")
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	outputFile := "opengrep.json"
	spec := ExecutionSpec{
		APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "opengrep", ToolID: "opengrep", ToolPath: toolPath, ToolDigest: fileDigestReference(t, toolPath),
		StatePath: statePath, StateDigest: stateDigest, RuntimeDigest: runtimeDigest, RulePackPath: rulePath, RulePackDigest: ruleDigest,
		OutputFile: outputFile, OutputMediaType: "application/json",
		Arguments: []string{"scan", "--config", rulePath, "--json", "--json-output", filepath.Join(temporary, outputFile), targetPath}, TargetRoot: targetPath, TemporaryDir: temporary,
		Environment:    map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"},
		TimeoutSeconds: 1200, Sandbox: strongSandbox(),
	}
	outcome, err := (HostRunner{Registry: registry, Host: productionDockerHost(t, runtimeDigest), Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-opengrep-production-candidate", "sast")
	if err != nil || outcome.Status != Succeeded || len(outcome.RawArtifacts) != 1 {
		t.Fatalf("Opengrep production candidate failed: %#v %v", outcome, err)
	}
	var raw struct {
		Results []json.RawMessage `json:"results"`
	}
	contents, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(outcome.RawArtifacts[0].Path)))
	if err != nil || json.Unmarshal(contents, &raw) != nil || len(raw.Results) != 5 {
		t.Fatalf("Opengrep raw evidence is not the expected JSON result: %v", err)
	}
}

func TestScanCodeProductionCandidateThroughHostRunner(t *testing.T) {
	requireProductionCandidateIntegration(t)
	toolPath := requiredEnvironment(t, "PAO_SCANCODE_TOOL_PATH")
	statePath := requiredEnvironment(t, "PAO_SCANCODE_STATE_PATH")
	targetPath := requiredEnvironment(t, "PAO_SCANCODE_TARGET_PATH")
	runtimeDigest := requiredEnvironment(t, "PAO_SCANCODE_RUNTIME_DIGEST")
	licenseDigest := requiredEnvironment(t, "PAO_SCANCODE_LICENSE_DATA_DIGEST")
	stateDigest := fileDigestReference(t, filepath.Join(statePath, preparedStateManifestName))
	now := time.Now().UTC()
	registry, err := toolchain.New([]toolchain.Record{{
		ID: "scancode", Version: "32.5.0", SHA256: fileDigestHex(t, toolPath), SourceLicense: "Apache-2.0", Redistribution: "user-installed-only",
		StateSHA256: stateDigest[len("sha256:"):], RuntimeSHA256: runtimeDigest[len("sha256:"):], LicenseDataSHA256: licenseDigest[len("sha256:"):],
		StateAt: now, RuntimeAt: now, LicenseDataAt: now,
		StateEnvironment: map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := loadProductionManifest(t, "scancode")
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	outputFile := "scancode.json"
	spec := ExecutionSpec{
		APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "scancode", ToolID: "scancode", ToolPath: toolPath, ToolDigest: fileDigestReference(t, toolPath),
		StatePath: statePath, StateDigest: stateDigest, StateEntrypoint: "scancode-toolkit-v32.5.0/venv/bin/scancode",
		RuntimeDigest: runtimeDigest, LicenseDataDigest: licenseDigest, OutputFile: outputFile, OutputMediaType: "application/json",
		Arguments: []string{"--license", "--copyright", "--package", "--processes", "1", "--timeout", "300", "--json", filepath.Join(temporary, outputFile), targetPath}, TargetRoot: targetPath, TemporaryDir: temporary,
		Environment:    map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"},
		TimeoutSeconds: 1800, Sandbox: strongSandbox(),
	}
	outcome, err := (HostRunner{Registry: registry, Host: productionDockerHost(t, runtimeDigest), Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-scancode-production-candidate", "license")
	if err != nil || outcome.Status != Succeeded || len(outcome.RawArtifacts) != 1 {
		t.Fatalf("ScanCode production candidate failed: %#v %v", outcome, err)
	}
	var raw struct {
		Files []struct {
			DetectedLicenseExpression string `json:"detected_license_expression"`
		} `json:"files"`
	}
	contents, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(outcome.RawArtifacts[0].Path)))
	if err != nil || json.Unmarshal(contents, &raw) != nil || len(raw.Files) != 2 || raw.Files[1].DetectedLicenseExpression != "apache-2.0" {
		t.Fatalf("ScanCode raw evidence is not the expected JSON result: %v", err)
	}
}

func requireProductionCandidateIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("PAO_PRODUCTION_CANDIDATE_INTEGRATION") != "1" {
		t.Skip("set PAO_PRODUCTION_CANDIDATE_INTEGRATION=1 for local verified-candidate tests")
	}
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func fileDigestHex(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func fileDigestReference(t *testing.T, path string) string { return "sha256:" + fileDigestHex(t, path) }

func loadProductionManifest(t *testing.T, id string) adapter.Manifest {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "adapters", id, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func productionDockerHost(t *testing.T, runtimeDigest string) DockerHost {
	t.Helper()
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	return testDockerHost(t, dockerPath, runtimeDigest)
}
