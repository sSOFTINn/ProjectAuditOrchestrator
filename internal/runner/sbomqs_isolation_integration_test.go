package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/adapters/sbomqs"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestSBOMQSDockerInputOnlyIsolation(t *testing.T) {
	if os.Getenv("PAO_SBOMQS_DOCKER_INTEGRATION") != "1" {
		t.Skip("opt-in synthetic Docker acceptance")
	}
	image := os.Getenv("PAO_SBOMQS_TEST_IMAGE")
	if !sha256Reference.MatchString(image) {
		t.Fatal("PAO_SBOMQS_TEST_IMAGE must identify an existing immutable local image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tool := filepath.Join(t.TempDir(), "sbomqs-probe")
	build := exec.CommandContext(ctx, goBinary(t), "build", "-trimpath", "-o", tool, repositoryPath(t, "testdata", "sbomqs-isolation", "main.go"))
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic probe: %v %s", err, output)
	}
	toolData, err := os.ReadFile(tool)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(toolData)
	registry, err := toolchain.New([]toolchain.Record{{ID: "sbomqs", Version: "synthetic", SHA256: hex.EncodeToString(sum[:]), SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: image[7:], RuntimeAt: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	input, err := store.PutRaw("application/vnd.cyclonedx+json", body, "synthetic-syft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRaw("application/json", []byte(`{"synthetic_private_neighbor":true}`), "other-scanner"); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	sentinel := filepath.Join(target, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(store.Root(), filepath.FromSlash(input.Path))
	spec := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "sbomqs", ToolID: "sbomqs", ToolPath: tool, ToolDigest: "sha256:" + hex.EncodeToString(sum[:]), RuntimeDigest: image, InputPath: inputPath, InputDigest: input.SHA256, TargetRoot: target, TemporaryDir: t.TempDir(), Arguments: []string{"score", inputPath, "--legacy", "--json"}, TimeoutSeconds: 60, Sandbox: strongSandbox()}
	host := testDockerHost(t, dockerBinary(t), image)
	manifest, err := adapter.LoadFile(repositoryPath(t, "adapters", "sbomqs", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest.CompatibleToolVersions = []string{"synthetic"}
	result, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(ctx, spec, manifest, recordDigest, recordDigest, "synthetic-quality", "sbom-quality")
	if err != nil || result.Status != Succeeded || len(result.RawArtifacts) != 1 {
		for _, d := range result.Diagnostics {
			data, _ := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(d.Artifact.Path)))
			t.Logf("synthetic diagnostic: %s", data)
		}
		t.Fatalf("isolated input-only probe failed: %s %v", result.Status, err)
	}
	raw, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(result.RawArtifacts[0].Path)))
	if err != nil || sbomqs.Parse(raw).Status != "SUCCEEDED" || !bytes.Contains(raw, []byte(`"synthetic_isolation_verified":true`)) {
		t.Fatalf("missing probe evidence: %s %v", raw, err)
	}
	after, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(body, after) {
		t.Fatal("SBOM changed")
	}
	after, err = os.ReadFile(sentinel)
	if err != nil || string(after) != "unchanged" {
		t.Fatal("target changed")
	}
}

// TestSBOMQSUpstreamCandidateCompatibility is opt-in because it runs an exact,
// separately downloaded candidate. It neither installs nor approves that file.
func TestSBOMQSUpstreamCandidateCompatibility(t *testing.T) {
	if os.Getenv("PAO_SBOMQS_UPSTREAM_INTEGRATION") != "1" {
		t.Skip("opt-in upstream sbomqs candidate validation")
	}
	image := os.Getenv("PAO_SBOMQS_TEST_IMAGE")
	if !sha256Reference.MatchString(image) {
		t.Fatal("PAO_SBOMQS_TEST_IMAGE must identify an existing immutable local image")
	}
	candidate := os.Getenv("PAO_SBOMQS_CANDIDATE_PATH")
	expected := os.Getenv("PAO_SBOMQS_CANDIDATE_SHA256")
	if candidate == "" || len(expected) != 64 {
		t.Fatal("candidate path and 64-character SHA-256 are required")
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		t.Fatal("candidate file does not match the supplied SHA-256")
	}
	registry, err := toolchain.New([]toolchain.Record{{ID: "sbomqs", Version: "2.1.1", SHA256: expected, SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", RuntimeSHA256: image[7:], RuntimeAt: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:9b1deb4d-3b7d-4bad-9bdd-2b0d7b3b0c50","version":1,"metadata":{"component":{"type":"application","name":"pao-synthetic","version":"1.0.0"}},"components":[{"type":"library","name":"example","version":"1.0.0","licenses":[{"license":{"id":"MIT"}}]}]}`)
	input, err := store.PutRaw("application/vnd.cyclonedx+json", body, "synthetic-upstream")
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	sentinel := filepath.Join(target, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(store.Root(), filepath.FromSlash(input.Path))
	spec := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "sbomqs", ToolID: "sbomqs", ToolPath: candidate, ToolDigest: "sha256:" + expected, RuntimeDigest: image, InputPath: inputPath, InputDigest: input.SHA256, TargetRoot: target, TemporaryDir: t.TempDir(), Arguments: []string{"score", inputPath, "--legacy", "--json"}, TimeoutSeconds: 60, Sandbox: strongSandbox()}
	host := testDockerHost(t, dockerBinary(t), image)
	manifest, err := adapter.LoadFile(repositoryPath(t, "adapters", "sbomqs", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "upstream-quality", "sbom-quality")
	if err != nil || result.Status != Succeeded || len(result.RawArtifacts) != 1 {
		t.Fatalf("upstream candidate execution failed: %s %v", result.Status, err)
	}
	raw, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(result.RawArtifacts[0].Path)))
	if err != nil {
		t.Fatal(err)
	}
	parsed := sbomqs.Parse(raw)
	if parsed.Status != "SUCCEEDED" || parsed.Score < 0 || parsed.Score > 10 {
		t.Fatalf("upstream legacy JSON is incompatible: %#v", parsed)
	}
	after, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(body, after) {
		t.Fatal("captured SBOM changed")
	}
	after, err = os.ReadFile(sentinel)
	if err != nil || string(after) != "unchanged" {
		t.Fatal("target changed")
	}
}
