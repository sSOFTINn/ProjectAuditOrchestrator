package auditresult

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func syntheticRun(t *testing.T, overrides map[string]string) (string, plan.Plan, runner.Record, *toolchain.Registry) {
	t.Helper()
	root := t.TempDir()
	targetRoot := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(targetRoot, ".github", "workflows"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{"go.mod": "module synthetic", ".github/workflows/demo.yml": "name: synthetic"} {
		if err := os.WriteFile(filepath.Join(targetRoot, filepath.FromSlash(path)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := target.SnapshotRoot(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	var manifests []adapter.Manifest
	var tools []toolchain.Record
	for _, id := range []string{"syft", "sbomqs", "grype", "osv-scanner", "trivy", "gitleaks", "opengrep", "zizmor", "scancode", "reuse"} {
		manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", id, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := adapter.LoadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, m)
		tools = append(tools, toolchain.Record{ID: id, Version: "synthetic-1", SHA256: normalize.Fingerprint(id), SourceLicense: "MIT", Redistribution: "user-installed"})
	}
	lock, err := plan.BuildConfiguredFromManifests(snapshot, "mvp", "sha256:"+normalize.Fingerprint("config"), manifests)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := toolchain.New(tools)
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(root, "evidence")
	store, err := artifact.Open(evidence)
	if err != nil {
		t.Fatal(err)
	}
	record := runner.Record{Version: runner.RunRecordVersion, PlanDigest: lock.PlanDigest, TargetBefore: snapshot, TargetAfter: snapshot}
	var qualityNode *plan.AdapterNode
	var cycloneDX artifact.RawArtifact
	for index := range lock.Nodes {
		n := &lock.Nodes[index]
		if n.ID == "sbomqs" {
			qualityNode = n
			continue
		}
		body := nativeFixtures[n.ID]
		if override, ok := overrides[n.ID]; ok {
			body = override
		}
		execID := "synthetic-" + n.ID
		media := "application/json"
		if n.ID == "reuse" || n.ID == "zizmor" {
			media = "application/octet-stream"
		}
		if n.ID == "syft" {
			media = "application/vnd.syft+json"
		}
		raw, err := store.PutRaw(media, []byte(body), execID)
		if err != nil {
			t.Fatal(err)
		}
		e := runner.ToolExecution{ID: execID, AdapterID: n.ID, ToolID: n.ID, ToolDigest: "sha256:" + normalize.Fingerprint(n.ID), PlanDigest: lock.PlanDigest, ConfigDigest: n.ConfigDigest, ManifestDigest: n.ManifestDigest, Status: runner.Succeeded, Coverage: toolchain.Coverage{ToolID: n.ID, Capability: n.Capability, Status: runner.Succeeded, Reason: "synthetic"}, RawArtifacts: []artifact.RawArtifact{raw}, Sandbox: runner.SandboxProperties{Isolation: runner.StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}}
		if n.ID == "syft" {
			components := []map[string]string{}
			for _, item := range parseNative("syft", []byte(body)).Items {
				if item.Category == "inventory" {
					components = append(components, map[string]string{"name": item.Component, "version": item.ComponentVersion, "purl": item.PURL})
				}
			}
			sbom, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components})
			if err != nil {
				t.Fatal(err)
			}
			cycloneDX, err = store.PutRaw("application/vnd.cyclonedx+json", sbom, execID)
			if err != nil {
				t.Fatal(err)
			}
			e.RawArtifacts = append(e.RawArtifacts, cycloneDX)
		}
		record.Executions = append(record.Executions, e)
	}
	if qualityNode == nil || cycloneDX.SHA256 == "" {
		t.Fatal("synthetic quality lineage is incomplete")
	}
	qualityID := "synthetic-sbomqs"
	qualityRaw, err := store.PutRaw("application/json", []byte(qualityFixture), qualityID)
	if err != nil {
		t.Fatal(err)
	}
	record.Executions = append(record.Executions, runner.ToolExecution{ID: qualityID, AdapterID: "sbomqs", ToolID: "sbomqs", ToolDigest: "sha256:" + normalize.Fingerprint("sbomqs"), PlanDigest: lock.PlanDigest, ConfigDigest: qualityNode.ConfigDigest, ManifestDigest: qualityNode.ManifestDigest, Status: runner.Succeeded, Coverage: toolchain.Coverage{ToolID: "sbomqs", Capability: qualityNode.Capability, Status: runner.Succeeded, Reason: "synthetic"}, InputArtifact: &cycloneDX, RawArtifacts: []artifact.RawArtifact{qualityRaw}, Sandbox: runner.SandboxProperties{Isolation: runner.StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}})
	return evidence, lock, record, registry
}

func TestUnifiedNineScannerReportAndDeterminism(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, nil)
	r := Build(root, lock, record, catalog, false)
	if !r.CoverageComplete || r.Status != "REVIEW_REQUIRED" || len(r.Observations) != 9 || len(r.SBOMQuality) != 1 || len(r.Findings) != 8 || len(r.LicenseReview) != 1 {
		t.Fatalf("unexpected report: %#v", r)
	}
	for _, f := range r.Findings {
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	p := r.Portable()
	if p.SecurityFindings != 6 || p.LicenseQuestions != 2 || p.Inventory != 1 || p.Severities["UNKNOWN"] != 2 {
		t.Fatalf("counts: %#v", p)
	}
	first, err := r.Files()
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(record.Executions)-1; i < j; i, j = i+1, j-1 {
		record.Executions[i], record.Executions[j] = record.Executions[j], record.Executions[i]
	}
	second, err := Build(root, lock, record, catalog, false).Files()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Summary, second.Summary) || !bytes.Equal(first.PortableJSON, second.PortableJSON) || !bytes.Equal(first.PrivateJSON, second.PrivateJSON) || !bytes.Equal(first.FindingsJSONL, second.FindingsJSONL) {
		t.Fatal("nondeterministic output")
	}
	for _, data := range [][]byte{first.Summary, first.PortableJSON} {
		for _, s := range []string{root, "demo.txt", "demo.py", "synthetic.rule", "PAO_SYNTHETIC_SECRET_TEST", "private message", "must never be copied", "MIT OR Apache-2.0"} {
			if bytes.Contains(data, []byte(s)) {
				t.Fatalf("portable leaked %q", s)
			}
		}
	}
	if bytes.Contains(first.PrivateJSON, []byte("PAO_SYNTHETIC_SECRET_TEST")) {
		t.Fatal("copied raw secret into normalized details")
	}
	// Optional developer-only export of synthetic artifacts, exclusively into a NEW directory.
	if dest := os.Getenv("PAO_SYNTHETIC_REPORT_DIR"); dest != "" {
		if !filepath.IsAbs(dest) {
			t.Fatal("demo directory must be absolute")
		}
		if err := os.Mkdir(dest, 0700); err != nil {
			t.Fatal(err)
		}
		first.Summary = append([]byte("> Демонстрація на вигаданих тестових даних. Це не аудит вашого проєкту. Посилання на докази належать тимчасовому тесту.\n\n"), first.Summary...)
		for name, data := range map[string][]byte{"SUMMARY.md": first.Summary, "report.json": first.PortableJSON, "synthetic-private.json": first.PrivateJSON, "findings.jsonl": first.FindingsJSONL} {
			if err := os.WriteFile(filepath.Join(dest, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPartialKeepsKnownFindingsWithoutPassing(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, map[string]string{"opengrep": strings.Replace(nativeFixtures["opengrep"], `"errors":[]`, `"errors":[{"message":"failed"}]`, 1)})
	r := Build(root, lock, record, catalog, false)
	if r.CoverageComplete || r.Status != "INCOMPLETE" || len(r.Findings) != 8 {
		t.Fatal(r)
	}
	for i := range record.Executions {
		if record.Executions[i].AdapterID == "grype" {
			record.Executions[i].Status = runner.Partial
			record.Executions[i].Coverage.Status = runner.Partial
		}
	}
	r = Build(root, lock, record, catalog, false)
	if r.CoverageComplete || len(r.Findings) != 8 {
		t.Fatal("lost known partial findings")
	}
}

func TestSBOMQualityNeverExportsPositiveScoreForIncompleteCoverage(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, nil)
	for i := range record.Executions {
		if record.Executions[i].AdapterID == "sbomqs" {
			record.Executions[i].Status = runner.Unavailable
			record.Executions[i].Coverage.Status = runner.Unavailable
			record.Executions[i].Coverage.ReasonCode = toolchain.ReasonToolUnverified
			record.Executions[i].Coverage.Reason = "synthetic missing approval"
			record.Executions[i].RawArtifacts = nil
			record.Executions[i].InputArtifact = nil
		}
	}
	r := Build(root, lock, record, catalog, false)
	if r.CoverageComplete || r.Status != "INCOMPLETE" || len(r.SBOMQuality) != 0 || len(r.Portable().SBOMQualityScores) != 0 {
		t.Fatalf("incomplete sbom-quality was presented as positive: %#v", r)
	}
}

func TestCycloneDXQualityKeepsMissingFieldsForManualReviewWithoutNames(t *testing.T) {
	quality, err := inspectCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"private-component"},{"version":"1.0","licenses":[{"license":{"id":"MIT"}}],"supplier":{"name":"vendor"}}]}`))
	if err != nil || quality.name != 1 || quality.version != 1 || quality.license != 1 || quality.supplier != 1 {
		t.Fatalf("missing fields were not classified: %#v %v", quality, err)
	}
	if _, err := inspectCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":"wrong"}`)); err == nil {
		t.Fatal("unsupported CycloneDX was accepted")
	}

	root, lock, record, catalog := syntheticRun(t, nil)
	store, err := artifact.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	privateCycloneDX, err := store.PutRaw("application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"private-component"}]}`), "synthetic-syft")
	if err != nil {
		t.Fatal(err)
	}
	for i := range record.Executions {
		switch record.Executions[i].AdapterID {
		case "syft":
			record.Executions[i].RawArtifacts[1] = privateCycloneDX
		case "sbomqs":
			record.Executions[i].InputArtifact = &privateCycloneDX
		}
	}
	files, err := Build(root, lock, record, catalog, false).Files()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(files.PortableJSON, []byte("private-component")) || bytes.Contains(files.Summary, []byte("private-component")) {
		t.Fatal("portable report leaked a component name from CycloneDX evidence")
	}
}

func TestSBOMQualityIdentityIsStableAcrossRepeatedOfflineSyntheticRuns(t *testing.T) {
	var want SBOMQualityObservation
	for attempt := 0; attempt < 10; attempt++ {
		root, lock, record, catalog := syntheticRun(t, nil)
		quality := Build(root, lock, record, catalog, false).SBOMQuality
		if len(quality) != 1 || quality[0].Score != 8.5 {
			t.Fatalf("attempt %d has no deterministic quality result: %#v", attempt, quality)
		}
		if attempt == 0 {
			want = quality[0]
			continue
		}
		if quality[0].ID != want.ID || quality[0].SBOMEvidence != want.SBOMEvidence || quality[0].ResultEvidence != want.ResultEvidence || quality[0].Score != want.Score {
			t.Fatalf("attempt %d changed quality identity: got %#v, want %#v", attempt, quality[0], want)
		}
	}
}

func TestRawTamperingAndLineageAreRejected(t *testing.T) {
	for _, mode := range []string{"tamper", "traversal", "size", "missing", "duplicate", "foreign-plan", "wrong-tool", "manifest", "target-drift", "incomplete-snapshot", "unknown-reason", "no-findings-contradiction", "extra-execution", "multiple-raw"} {
		t.Run(mode, func(t *testing.T) {
			root, lock, record, catalog := syntheticRun(t, nil)
			e := &record.Executions[0]
			switch mode {
			case "tamper":
				path := filepath.Join(root, filepath.FromSlash(e.RawArtifacts[0].Path))
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`[]`), 0600); err != nil {
					t.Fatal(err)
				}
			case "traversal":
				e.RawArtifacts[0].Path = "../outside"
			case "size":
				e.RawArtifacts[0].Size++
			case "missing":
				record.Executions = record.Executions[1:]
			case "duplicate":
				record.Executions = append(record.Executions, *e)
			case "foreign-plan":
				e.PlanDigest = "sha256:" + normalize.Fingerprint("foreign")
			case "wrong-tool":
				e.ToolDigest = "sha256:" + normalize.Fingerprint("wrong")
			case "manifest":
				e.ManifestDigest = "sha256:" + normalize.Fingerprint("wrong")
			case "target-drift":
				record.TargetAfter.TargetID = "sha256:" + normalize.Fingerprint("changed")
			case "incomplete-snapshot":
				record.TargetAfter.Complete = false
			case "unknown-reason":
				e.Coverage.ReasonCode = "C:\\PRIVATE\\secret"
			case "no-findings-contradiction":
				for i := range record.Executions {
					if record.Executions[i].AdapterID == "gitleaks" {
						record.Executions[i].Status = runner.NoFindings
						record.Executions[i].Coverage.Status = runner.NoFindings
					}
				}
			case "extra-execution":
				extra := *e
				extra.AdapterID = "private-unknown"
				record.Executions = append(record.Executions, extra)
			case "multiple-raw":
				e.RawArtifacts = append(e.RawArtifacts, e.RawArtifacts[0])
			}
			r := Build(root, lock, record, catalog, false)
			if r.CoverageComplete || r.Status != "INCOMPLETE" {
				t.Fatalf("accepted %s: %#v", mode, r)
			}
			f, err := r.Files()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(f.Summary, []byte("PRIVATE")) || bytes.Contains(f.PortableJSON, []byte("private-unknown")) {
				t.Fatal("untrusted lineage text leaked")
			}
		})
	}
}

func TestPathsRulesAndMessagesStayPrivate(t *testing.T) {
	raw := `[{"RuleID":"<script>PAO_SYNTHETIC_SECRET_TEST</script>","File":"C:\\PRIVATE\\user@example.invalid\\demo.txt","StartLine":1,"Secret":"never copy"}]`
	root, lock, record, catalog := syntheticRun(t, map[string]string{"gitleaks": raw})
	r := Build(root, lock, record, catalog, false)
	files, err := r.Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{files.Summary, files.PortableJSON} {
		for _, bad := range []string{"<script>", "PRIVATE", "example.invalid", "never copy", "PAO_SYNTHETIC_SECRET_TEST"} {
			if bytes.Contains(data, []byte(bad)) {
				t.Fatalf("leak %s", bad)
			}
		}
	}
	for _, f := range r.Findings {
		if f.ScannerID == "gitleaks" && len(f.Locations) != 0 {
			t.Fatal("unsafe canonical location")
		}
	}
	var private Result
	if err := json.Unmarshal(files.PrivateJSON, &private); err != nil {
		t.Fatal(err)
	}
	if len(private.Findings) != len(r.Findings) {
		t.Fatal("private details lost")
	}
}

func TestCompoundLicenseWithoutValidatedGrammarRequiresReview(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, map[string]string{"scancode": strings.Replace(nativeFixtures["scancode"], "MIT OR Apache-2.0", "MIT Apache-2.0", 1)})
	r := Build(root, lock, record, catalog, false)
	if r.Portable().LicenseQuestions != 2 {
		t.Fatal("invalid compound license disappeared from review")
	}
}

func TestRawReaderRefusesLinks(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, nil)
	ref := record.Executions[0].RawArtifacts[0]
	path := filepath.Join(root, filepath.FromSlash(ref.Path))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "raw-copy")
	if err := os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unavailable on this host: %v", err)
	}
	r := Build(root, lock, record, catalog, false)
	if r.CoverageComplete {
		t.Fatal("followed evidence symlink")
	}
}
