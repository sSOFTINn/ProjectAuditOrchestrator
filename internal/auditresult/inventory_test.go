package auditresult

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/detect"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func syntheticDependencyRun(t *testing.T, paths []string, syftBody string) (string, plan.Plan, runner.Record, *toolchain.Registry) {
	t.Helper()
	root, _, record, catalog := syntheticRun(t, map[string]string{"syft": syftBody})
	targetRoot := t.TempDir()
	for _, path := range paths {
		file := filepath.Join(targetRoot, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		// Contents are synthetic. Filename-only detection intentionally never
		// interprets a custom lock as a supported package-manager format.
		if err := os.WriteFile(file, []byte("synthetic-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := target.SnapshotRoot(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	var manifests []adapter.Manifest
	for _, e := range record.Executions {
		manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", e.AdapterID, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := adapter.LoadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, m)
	}
	lock, err := plan.BuildConfiguredFromManifests(snapshot, "mvp", "sha256:"+normalize.Fingerprint("config"), manifests)
	if err != nil {
		t.Fatal(err)
	}
	record.PlanDigest, record.TargetBefore, record.TargetAfter = lock.PlanDigest, snapshot, snapshot
	for i := range record.Executions {
		e := &record.Executions[i]
		e.PlanDigest = lock.PlanDigest
		for _, n := range lock.Nodes {
			if n.ID != e.AdapterID {
				continue
			}
			if n.Status == "SKIPPED_NOT_APPLICABLE" || n.Status == "UNSUPPORTED" {
				e.Status, e.Coverage.Status = runner.Unsupported, runner.Unsupported
				e.RawArtifacts = nil
				e.Coverage.ReasonCode = toolchain.ReasonNotApplicable
				if n.Status == "UNSUPPORTED" {
					e.Coverage.ReasonCode = n.SupportReasons[0]
				}
			}
		}
	}
	return root, lock, record, catalog
}

func TestInventoryControlsSeparateActionsFromPythonAndPreserveExecutionMeaning(t *testing.T) {
	actionsOnly := `{"schema":{"version":"16.1.3"},"artifacts":[{"name":"synthetic-action","version":"v1","type":"github-action","purl":"pkg:github/example/synthetic-action@v1"}]}`
	for _, tc := range []struct {
		name      string
		paths     []string
		syft      string
		execution bool
		analysis  bool
		gap       string
	}{
		{"go-positive", []string{"go.mod"}, nativeFixtures["syft"], true, true, ""},
		{"go-negative-empty", []string{"go.mod"}, `{"schema":{"version":"16.1.3"},"artifacts":[]}`, true, false, "EXPECTED_ECOSYSTEM_NOT_OBSERVED"},
		{"no-dependencies", []string{"README.md"}, `{"schema":{"version":"16.1.3"},"artifacts":[]}`, true, true, ""},
		{"workflow-only", []string{".github/workflows/ci.yml"}, actionsOnly, true, true, ""},
		{"python-actions-only", []string{"pyproject.toml", "requirements.txt"}, actionsOnly, false, false, "EXPECTED_ECOSYSTEM_NOT_OBSERVED"},
		{"mixed-actions-only", []string{"go.mod", "pyproject.toml", "requirements.lock", "build-requirements.lock"}, actionsOnly, true, false, "UNSUPPORTED_INPUT_FORMAT"},
		{"mixed-with-python", []string{"go.mod", "requirements.txt"}, `{"schema":{"version":"16.1.3"},"artifacts":[{"name":"go-synthetic","version":"1.2.3","purl":"pkg:golang/example@1.2.3"},{"name":"python-synthetic","version":"2.3.4","type":"python","purl":"pkg:pypi/example@2.3.4"}]}`, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, lock, record, catalog := syntheticDependencyRun(t, tc.paths, tc.syft)
			r := Build(root, lock, record, catalog, false)
			if r.CoverageComplete != tc.execution || r.AnalysisCoverageComplete != tc.analysis {
				t.Fatalf("execution vs analysis: %+v, %+v", r.Coverage, r.InventoryCoverage)
			}
			if !tc.analysis && r.Status != "INCOMPLETE" {
				t.Fatalf("known analysis gap yielded %s", r.Status)
			}
			if tc.gap != "" && !hasInventoryGap(r.InventoryCoverage, tc.gap) {
				t.Fatalf("gap %s absent: %+v", tc.gap, r.InventoryCoverage)
			}
			if strings.Contains(tc.name, "actions-only") && containsString(r.InventoryCoverage.ObservedEcosystems, "PyPI") {
				t.Fatal("Actions were counted as Python coverage")
			}
			if tc.name == "mixed-with-python" && (!r.InventoryCoverage.Adequate || len(r.InventoryCoverage.ObservedEcosystems) != 2) {
				t.Fatal("positive Go/PyPI inventory was lost")
			}
			if tc.name == "python-actions-only" {
				for _, c := range r.Coverage {
					if c.Scanner == "osv-scanner" && (c.ExecutionStatus != runner.Unsupported || c.ParsingStatus != "UNSUPPORTED_INPUT" || !containsString(c.Reasons, "DB_ECOSYSTEM_UNSUPPORTED") || containsString(c.Reasons, "INVALID_EXECUTION_LINEAGE")) {
						t.Fatalf("unsupported feed was confused with execution/parsing failure: %+v", c)
					}
				}
			}
			// An informational SBOM score must never close support/inventory gaps.
			if len(r.SBOMQuality) != 1 || (r.SBOMQuality[0].Score > 0 && !tc.analysis && r.AnalysisCoverageComplete) {
				t.Fatal("quality score changed analysis coverage")
			}
			files, err := r.Files()
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"synthetic-action", "go-synthetic", "python-synthetic", "example@", root} {
				if bytes.Contains(files.PortableJSON, []byte(text)) || bytes.Contains(files.Summary, []byte(text)) {
					t.Fatalf("portable inventory leaked %q", text)
				}
			}
		})
	}
}

func TestInventoryFormatAndVersionGapsHaveExactScope(t *testing.T) {
	lock := plan.Plan{Detected: detect.Detect(target.Snapshot{Files: []target.FileEntry{{Path: "pyproject.toml"}, {Path: "requirements.lock"}, {Path: "build-requirements.lock"}}})}
	parsed := parseNative("syft", []byte(`{"schema":{"version":"16.1.3"},"artifacts":[{"name":"synthetic-private-python","type":"python","version":"2.4.6","purl":"pkg:pypi/synthetic@2.4.6"}]}`))
	if parsed.Status != "PARSED" || len(parsed.Items) != 1 || parsed.Items[0].ComponentVersion != "2.4.6" {
		t.Fatal("positive native component/version control failed")
	}
	coverage := []Coverage{{Scanner: "syft", Complete: true, ParsingStatus: "PARSED"}}
	observations := []Observation{{Scanner: "syft", Native: parsed.Items[0]}}
	got := assessInventory(lock, coverage, observations)
	if got.Adequate || len(got.Gaps) != 2 || got.Gaps[0].Format != "build-requirements.lock" || got.Gaps[0].Scope != "build" || got.Gaps[1].Format != "requirements.lock" {
		t.Fatalf("custom formats lost: %+v", got)
	}
	lock.Detected = detect.Detect(target.Snapshot{Files: []target.FileEntry{{Path: "requirements.txt"}}})
	if got := assessInventory(lock, coverage, observations); !got.Adequate || got.Status != "ADEQUATE_FOR_DETECTED_ECOSYSTEMS" {
		t.Fatalf("positive ecosystem control: %+v", got)
	}
	observations[0].Native.ComponentVersion = ""
	if got := assessInventory(lock, coverage, observations); got.Adequate || !hasInventoryGap(got, "INVENTORY_VERSION_MISSING") {
		t.Fatalf("unpinned control: %+v", got)
	}
	coverage[0].Complete = false
	if got := assessInventory(lock, coverage, observations); got.Adequate || len(got.ObservedEcosystems) != 0 || !hasInventoryGap(got, "INVENTORY_EVIDENCE_UNAVAILABLE") {
		t.Fatalf("incomplete evidence became adequate: %+v", got)
	}
}

func TestManifestLimitationsAndUnknownMetadataStayBoundedAndPrivate(t *testing.T) {
	c := nodeCoverage(plan.AdapterNode{ID: "osv-scanner", Applicability: "APPLICABLE", SupportStatus: "UNSUPPORTED", SupportReasons: []string{"DB_ECOSYSTEM_UNSUPPORTED", "C:/PRIVATE/secret"}, Limitations: []string{"local-database-currently-covers-go-only", "C:/PRIVATE/secret"}})
	r := Result{Coverage: []Coverage{c}}
	files, err := r.Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{files.PortableJSON, files.Summary} {
		if bytes.Contains(data, []byte("PRIVATE")) || !bytes.Contains(data, []byte("local-database-currently-covers-go-only")) {
			t.Fatal("manifest support/limitation projection is not a whitelist")
		}
	}
}

func hasInventoryGap(coverage InventoryCoverage, code string) bool {
	for _, gap := range coverage.Gaps {
		if gap.Reason == code {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func TestCapturedSBOMMustAccountForNativeInventory(t *testing.T) {
	root, lock, record, catalog := syntheticDependencyRun(t, []string{"go.mod"}, nativeFixtures["syft"])
	store, err := artifact.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.PutRaw("application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), "synthetic-syft")
	if err != nil {
		t.Fatal(err)
	}
	for i := range record.Executions {
		e := &record.Executions[i]
		if e.AdapterID == "syft" {
			e.RawArtifacts[1] = ref
		}
		if e.AdapterID == "sbomqs" {
			e.InputArtifact = &ref
		}
	}
	r := Build(root, lock, record, catalog, false)
	if !r.CoverageComplete || r.AnalysisCoverageComplete || r.InventoryCoverage.Adequate || !hasInventoryGap(r.InventoryCoverage, "SBOM_EXPORT_INVENTORY_MISMATCH") {
		t.Fatalf("successful native/SBOM divergence presented as adequate: %+v", r.InventoryCoverage)
	}
	if len(r.SBOMQuality) != 1 || r.SBOMQuality[0].Score != 8.5 {
		t.Fatal("informational score was lost, rather than keeping the distinct inventory gap")
	}
}

func TestInventoryExportComparisonChecksVersionPURLAndNestedComponents(t *testing.T) {
	native := []nativeItem{{Category: "inventory", Component: "synthetic", ComponentVersion: "1", PURL: "pkg:pypi/synthetic@1"}}
	for _, tc := range []struct {
		components string
		match      bool
	}{
		{`[{"name":"synthetic","version":"1","purl":"pkg:pypi/synthetic@1"}]`, true},
		{`[{"name":"synthetic","version":"2","purl":"pkg:pypi/synthetic@1"}]`, false},
		{`[{"name":"synthetic","version":"1","purl":"pkg:golang/synthetic@1"}]`, false},
		{`[]`, false},
		{`[{"name":"synthetic","version":"1","purl":"pkg:pypi/synthetic@1","components":[{"name":"extra","version":"1"}]}]`, false},
	} {
		if got := consistentInventoryExport(native, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":`+tc.components+`}`)); got != tc.match {
			t.Fatalf("comparison %s: got %v", tc.components, got)
		}
	}
	if got := assessInventory(plan.Plan{Detected: detect.Result{Languages: []string{"go"}}}, nil, nil); got.Adequate || !hasInventoryGap(got, "INVENTORY_EXPECTATIONS_NOT_RECORDED") {
		t.Fatalf("legacy execution-only coverage upgraded to an inventory claim: %+v", got)
	}
}
