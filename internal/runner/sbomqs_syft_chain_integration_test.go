package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/adapters/sbomqs"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

// This is a chain compatibility test, not a new SBOM fixture. The operator must
// supply the exact raw CycloneDX captured by the installed Syft acceptance case.
// Only the declared captured input is mounted for the sbomqs adapter.
func TestAdditionalSBOMQSSyftCapturedChainThroughHostRunner(t *testing.T) {
	if os.Getenv("PAO_ADDITIONAL_SBOMQS_CHAIN_INTEGRATION") != "1" {
		t.Skip("set PAO_ADDITIONAL_SBOMQS_CHAIN_INTEGRATION=1 for the actual captured Syft chain")
	}
	root := additionalExistingPath(t, "PAO_ADDITIONAL_TOOLCHAIN_ROOT", true)
	catalogPath := additionalExistingPath(t, "PAO_ADDITIONAL_TOOLCHAIN_CATALOG", false)
	stage := additionalExistingPath(t, "PAO_ADDITIONAL_STAGE_ROOT", true)
	for _, protected := range []string{repositoryPath(t), root, filepath.Dir(catalogPath)} {
		if target.IsInside(protected, stage) || target.IsInside(stage, protected) {
			t.Fatal("staging must be separate from source, installed tools and catalog")
		}
	}
	if !target.IsInside(stage, os.TempDir()) {
		t.Fatal("child process TEMP/TMP must be inside the approved staging root")
	}
	inputPath := additionalExistingPath(t, "PAO_ADDITIONAL_CAPTURED_SYFT_SBOM_PATH", false)
	inputDigest := requiredEnvironment(t, "PAO_ADDITIONAL_CAPTURED_SYFT_SBOM_SHA256")
	if len(inputDigest) == 64 {
		inputDigest = "sha256:" + inputDigest
	}
	if !target.IsInside(stage, inputPath) || !sha256Reference.MatchString(inputDigest) {
		t.Fatal("captured Syft input must be an exact staging file with a lowercase SHA-256")
	}
	inputBytes := sbomqsChainRead(t, inputPath, 8<<20)
	if sbomqsChainDigest(inputBytes) != inputDigest {
		t.Fatal("actual captured Syft bytes do not match the operator-supplied digest")
	}
	syftArtifact := sbomqsChainSyftReference(t, inputPath, inputDigest, int64(len(inputBytes)))
	var cdx any
	if json.Unmarshal(inputBytes, &cdx) != nil {
		t.Fatal("captured Syft output is not JSON")
	}
	additionalAssertCycloneDX(t, cdx) // exact pinned default 1.7 and synthetic inventory
	cdxObject := additionalObject(t, cdx)
	componentCount := len(additionalArray(t, cdxObject["components"]))
	// sbomqs counts the BOM's subject component as well as its top-level
	// components; metadata.tools identifies producers and is not inventory.
	if metadata, ok := cdxObject["metadata"].(map[string]any); ok && metadata["component"] != nil {
		additionalObject(t, metadata["component"])
		componentCount++
	}
	catalog, err := toolchain.LoadCatalog(catalogPath, time.Now().UTC())
	if err != nil {
		t.Fatalf("current explicit catalog approval is unavailable: %v", err)
	}
	installed := additionalCatalogTool(t, catalog, "sbomqs")
	const upstreamSHA256 = "2ca59447712b11b9829c8e3fc1f899251d1313db4f7fdb4adf43f56a786fbd6c"
	manifest := loadProductionManifest(t, "sbomqs")
	if installed.Record.Version != "2.1.1" || installed.Record.SHA256 != upstreamSHA256 || installed.Record.SourceLicense != manifest.SourceLicense || installed.Record.Redistribution != "user-installed-only" || installed.Database != "" || installed.State != "" || installed.RulePack != "" {
		t.Fatal("sbomqs catalog record differs from the exact reviewed input-only candidate")
	}
	registry, err := toolchain.New([]toolchain.Record{installed.Record})
	if err != nil {
		t.Fatal(err)
	}
	toolPath := additionalRelativePath(t, root, installed.Binary)
	if fileDigestHex(t, toolPath) != upstreamSHA256 {
		t.Fatal("installed sbomqs bytes do not match their exact reviewed pin")
	}
	caseRoot := additionalPrivateDirectory(t, stage, "upstream-sbomqs-syft-chain-")
	t.Logf("retained actual Syft-to-sbomqs chain evidence: %s", caseRoot)
	targetRoot := additionalPrivateChild(t, caseRoot, "target")
	sentinel := filepath.Join(targetRoot, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged synthetic sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporary := additionalPrivateChild(t, caseRoot, "output")
	store, err := artifact.Open(additionalPrivateChild(t, caseRoot, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeDigest := "sha256:" + installed.Record.RuntimeSHA256
	spec := ExecutionSpec{
		APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "sbomqs", ToolID: "sbomqs",
		ToolPath: toolPath, ToolDigest: "sha256:" + upstreamSHA256, RuntimeDigest: runtimeDigest,
		InputPath: inputPath, InputDigest: inputDigest, TargetRoot: targetRoot, TemporaryDir: temporary,
		Environment: map[string]string{}, TimeoutSeconds: manifest.TimeoutSeconds,
		MaxOutputBytes: 8 << 20, MemoryMB: 512, Sandbox: strongSandbox(),
	}
	spec.Arguments, err = ManifestArguments(manifest, spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	before, err := target.SnapshotRootContext(ctx, targetRoot)
	if err != nil || !before.Complete {
		t.Fatalf("synthetic sentinel snapshot is incomplete: %v", err)
	}
	observation := &sbomqsChainFrozenObservation{}
	host := sbomqsChainObservedHost{DockerHost: productionDockerHost(t, runtimeDigest), observation: observation, caseRoot: caseRoot, expected: syftArtifact}
	outcome, runErr := (HostRunner{
		Registry: registry, Host: host, Artifacts: store,
		Progress: func(stage Stage) { t.Logf("sbomqs Syft chain: %s", stage) },
	}).ExecuteDeclared(ctx, spec, manifest, recordDigest, recordDigest, "exec-additional-sbomqs-syft-chain", "sbom-quality")
	after, snapshotErr := target.SnapshotRootContext(ctx, targetRoot)
	readback := sbomqsChainRead(t, inputPath, 8<<20)
	inputUnchanged := bytes.Equal(inputBytes, readback) && sbomqsChainDigest(readback) == inputDigest
	targetUnchanged := snapshotErr == nil && after.Complete && before.TargetID == after.TargetID && string(sbomqsChainRead(t, sentinel, 1024)) == "unchanged synthetic sentinel\n"
	additionalWriteJSON(t, filepath.Join(caseRoot, "execution.json"), struct {
		CatalogDigest   string                       `json:"catalog_digest"`
		OriginalRecord  toolchain.Record             `json:"original_record"`
		SyftArtifact    artifact.RawArtifact         `json:"syft_artifact"`
		Spec            ExecutionSpec                `json:"spec"`
		FrozenInput     sbomqsChainFrozenObservation `json:"frozen_input"`
		Before          target.Snapshot              `json:"target_before"`
		After           target.Snapshot              `json:"target_after"`
		Execution       ToolExecution                `json:"execution"`
		InputUnchanged  bool                         `json:"input_unchanged"`
		TargetUnchanged bool                         `json:"target_unchanged"`
	}{catalog.Digest, installed.Record, syftArtifact, spec, *observation, before, after, outcome, inputUnchanged, targetUnchanged})
	if !inputUnchanged || !targetUnchanged {
		t.Fatal("captured input or unmounted synthetic target changed")
	}
	if runErr != nil || outcome.Status != Succeeded || len(outcome.RawArtifacts) != 1 || !observation.Verified {
		t.Fatalf("actual Syft-to-sbomqs chain unavailable/failed (not PASS): status=%s diagnostic=%s reason=%s error=%v; evidence=%s", outcome.Status, outcome.DiagnosticCode, outcome.Coverage.Reason, runErr, caseRoot)
	}
	ref := outcome.RawArtifacts[0]
	raw := sbomqsChainRead(t, filepath.Join(store.Root(), filepath.FromSlash(ref.Path)), 8<<20)
	if ref.SHA256 != sbomqsChainDigest(raw) || ref.Size != int64(len(raw)) {
		t.Fatal("captured sbomqs bytes no longer match their immutable output reference")
	}
	parsed := sbomqs.Parse(raw)
	if parsed.Status != Succeeded || math.IsNaN(parsed.Score) || math.IsInf(parsed.Score, 0) || parsed.Score < 0 || parsed.Score > 10 {
		t.Fatalf("actual upstream sbomqs legacy parser rejected the captured Syft chain: status=%s reason=%s", parsed.Status, parsed.Reason)
	}
	var quality struct {
		Files []struct {
			Spec        string `json:"spec"`
			SpecVersion string `json:"spec_version"`
			Components  int    `json:"num_components"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &quality) != nil || len(quality.Files) != 1 || quality.Files[0].Spec != "cyclonedx" || quality.Files[0].SpecVersion != "1.7" || quality.Files[0].Components != componentCount {
		t.Fatal("sbomqs did not identify the actual CycloneDX 1.7 input and its complete component count")
	}
	additionalWriteJSON(t, filepath.Join(caseRoot, "acceptance.json"), struct {
		Tool            string               `json:"tool"`
		Version         string               `json:"version"`
		SyftArtifact    artifact.RawArtifact `json:"syft_artifact"`
		Parsed          sbomqs.Result        `json:"parsed"`
		InputUnchanged  bool                 `json:"input_unchanged"`
		TargetUnchanged bool                 `json:"target_unchanged"`
	}{"sbomqs", "2.1.1", syftArtifact, parsed, true, true})
}

func sbomqsChainDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sbomqsChainRead(t *testing.T, file string, limit int64) []byte {
	t.Helper()
	if err := auditconfig.CheckPath(file, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		t.Fatal("chain evidence file is unavailable, nonregular or oversized")
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !frozenUnchanged(info, opened) {
		t.Fatal("chain evidence file changed before bounded reading")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, afterErr := f.Stat()
	current, pathErr := os.Lstat(file)
	if err != nil || afterErr != nil || pathErr != nil || int64(len(data)) > limit || !frozenUnchanged(opened, after) || !frozenUnchanged(after, current) {
		t.Fatal("chain evidence file changed during bounded reading")
	}
	return data
}

func sbomqsChainSyftReference(t *testing.T, file, digest string, size int64) artifact.RawArtifact {
	t.Helper()
	artifactRoot := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	caseRoot := filepath.Dir(artifactRoot)
	if filepath.Dir(file) != filepath.Join(artifactRoot, "raw", "sha256") || filepath.Base(file) != strings.TrimPrefix(digest, "sha256:") || filepath.Base(artifactRoot) != "artifacts" || !strings.HasPrefix(filepath.Base(caseRoot), "upstream-syft-") {
		t.Fatal("input is not the exact raw address from a retained Syft acceptance case")
	}
	var receipt struct {
		OriginalRecord toolchain.Record `json:"original_record"`
		Spec           ExecutionSpec    `json:"spec"`
		Execution      ToolExecution    `json:"execution"`
	}
	if json.Unmarshal(sbomqsChainRead(t, filepath.Join(caseRoot, "execution.json"), 512<<10), &receipt) != nil {
		t.Fatal("retained Syft execution receipt is malformed")
	}
	manifestDigest, err := adapter.Digest(loadProductionManifest(t, "syft"))
	pin := additionalUpstreamPins["syft"]
	if err != nil || receipt.OriginalRecord.ID != "syft" || receipt.OriginalRecord.Version != pin.version || receipt.OriginalRecord.SHA256 != pin.sha256 || receipt.Spec.AdapterID != "syft" || receipt.Spec.ToolID != "syft" || receipt.Spec.ToolDigest != "sha256:"+pin.sha256 || receipt.Execution.Status != Succeeded || receipt.Execution.ToolID != "syft" || receipt.Execution.ManifestDigest != manifestDigest || receipt.Execution.ToolDigest != receipt.Spec.ToolDigest {
		t.Fatal("captured input is not linked to a successful exact pinned Syft HostRunner execution")
	}
	var found *artifact.RawArtifact
	for _, ref := range receipt.Execution.RawArtifacts {
		if ref.MediaType == "application/vnd.cyclonedx+json" {
			if found != nil || ref.SHA256 != digest || ref.Size != size || filepath.Join(artifactRoot, filepath.FromSlash(ref.Path)) != file || ref.ExecutionID != receipt.Execution.ID {
				t.Fatal("Syft raw artifact media type, address, SHA-256, size or execution lineage differs")
			}
			copy := ref
			found = &copy
		}
	}
	if found == nil {
		t.Fatal("successful Syft execution did not capture the supplied CycloneDX input")
	}
	return *found
}

type sbomqsChainFrozenObservation struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Verified bool   `json:"verified"`
}

// Preserve DockerHost's executable freezing, runtime identity, capability probes
// and real launch. This observer checks the exact private input delivered to it.
type sbomqsChainObservedHost struct {
	DockerHost
	observation *sbomqsChainFrozenObservation
	caseRoot    string
	expected    artifact.RawArtifact
}

func (h sbomqsChainObservedHost) prepareExecution(ctx context.Context, spec ExecutionSpec) (IsolationHost, func() error, error) {
	prepared, cleanup, err := h.DockerHost.prepareExecution(ctx, spec)
	if err != nil {
		return nil, cleanup, err
	}
	base, ok := prepared.(DockerHost)
	if !ok {
		return nil, nil, errors.Join(errors.New("chain host preparation changed the production host type"), cleanup())
	}
	h.DockerHost = base
	return h, cleanup, nil
}

func (h sbomqsChainObservedHost) Launch(ctx context.Context, spec ExecutionSpec) (LaunchResult, error) {
	if !spec.verifiedInputs || spec.AdapterID != "sbomqs" || spec.InputDigest != h.expected.SHA256 || !target.IsInside(h.caseRoot, spec.InputPath) {
		return LaunchResult{}, errors.New("chain launch did not receive the exact verified private input")
	}
	data, err := readDeclaredOutput(filepath.Dir(spec.InputPath), filepath.Base(spec.InputPath))
	if err != nil || int64(len(data)) != h.expected.Size || sbomqsChainDigest(data) != h.expected.SHA256 {
		return LaunchResult{}, errors.New("frozen chain input bytes differ from the captured Syft artifact")
	}
	*h.observation = sbomqsChainFrozenObservation{spec.InputPath, h.expected.SHA256, int64(len(data)), true}
	return h.DockerHost.Launch(ctx, spec)
}
