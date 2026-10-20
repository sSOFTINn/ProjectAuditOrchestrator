package auditresult

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

const emptyGoManifest = "module example.invalid/private-main\n\ngo 1.27.1\n"
const syftEmptyGo = `{"schema":{"version":"16.1.10"},"descriptor":{"configuration":{"catalogers":{"used":["go-module-file-cataloger"]}}},"artifacts":[]}`

func TestGoEmptyDeclarationsRequireContentCatalogerAndMatchingSBOM(t *testing.T) {
	for _, tc := range []struct {
		name, extraPath, extraContent, syft, cdx string
		adequate                                 bool
	}{
		{name: "empty", syft: syftEmptyGo, adequate: true},
		{name: "omitted-components", syft: syftEmptyGo, cdx: `{"bomFormat":"CycloneDX","specVersion":"1.6"}`, adequate: true},
		{name: "actions-only", syft: `{"schema":{"version":"16.1.10"},"descriptor":{"configuration":{"catalogers":{"used":["go-module-file-cataloger"]}}},"artifacts":[{"name":"private-action","version":"v1","type":"github-action"}]}`, adequate: true},
		{name: "all-empty-modules", extraPath: "nested/go.mod", extraContent: emptyGoManifest, syft: syftEmptyGo, adequate: true},
		{name: "populated", extraPath: "go.mod", extraContent: emptyGoManifest + "require example.invalid/private-dependency v1.2.3\n", syft: syftEmptyGo},
		{name: "populated-nested-module", extraPath: "nested/go.mod", extraContent: emptyGoManifest + "require example.invalid/private-dependency v1.2.3\n", syft: syftEmptyGo},
		{name: "checksum", extraPath: "go.sum", extraContent: "synthetic-checksum", syft: syftEmptyGo},
		{name: "workspace", extraPath: "go.work", extraContent: "go 1.27.1\nuse .\n", syft: syftEmptyGo},
		{name: "vendor", extraPath: "vendor/modules.txt", extraContent: "synthetic-vendor", syft: syftEmptyGo},
		{name: "go-vendor-source", extraPath: "vendor/example.invalid/dep/dep.go", extraContent: "package dep\n", syft: syftEmptyGo},
		{name: "non-go-vendor", extraPath: "schemas/vendor/schema.json", extraContent: "{}", syft: syftEmptyGo, adequate: true},
		{name: "cataloger-absent", syft: `{"schema":{"version":"16.1.10"},"artifacts":[]}`},
		{name: "cataloger-malformed", syft: `{"schema":{"version":"16.1.10"},"descriptor":{"configuration":{"catalogers":{"used":["go-module-file-cataloger",null]}}},"artifacts":[]}`},
		{name: "cataloger-duplicated", syft: `{"schema":{"version":"16.1.10"},"descriptor":{"configuration":{"catalogers":{"used":["go-module-file-cataloger","go-module-file-cataloger"]}}},"artifacts":[]}`},
		{name: "export-extra-package", syft: syftEmptyGo, cdx: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"private-extra","version":"1","purl":"pkg:golang/example.invalid/private-extra@1"}]}`},
		{name: "export-null", syft: syftEmptyGo, cdx: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := map[string]string{"go.mod": emptyGoManifest}
			if tc.extraPath != "" {
				contents[tc.extraPath] = tc.extraContent
			}
			root, lock, record, catalog := syntheticDependencyContentsRun(t, contents, tc.syft)
			if tc.cdx != "" {
				store, err := artifact.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				ref, err := store.PutRaw("application/vnd.cyclonedx+json", []byte(tc.cdx), "synthetic-syft")
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
			}
			r := Build(root, lock, record, catalog, false)
			if r.InventoryCoverage.Adequate != tc.adequate || r.AnalysisCoverageComplete != tc.adequate {
				t.Fatalf("empty declaration control: %+v; reasons=%v", r.InventoryCoverage, r.Reasons)
			}
			if tc.adequate && (r.Status != "REVIEW_REQUIRED" || len(r.InventoryCoverage.VerifiedEmptyDeclaredEcosystems) != 1 || containsString(r.InventoryCoverage.ObservedEcosystems, "Go")) {
				t.Fatalf("empty declarations became a fabricated scanner observation/verdict: %+v", r)
			}
			if !tc.adequate && len(r.InventoryCoverage.VerifiedEmptyDeclaredEcosystems) != 0 {
				t.Fatalf("incomplete or contradictory evidence retained a verified empty declaration: %+v", r.InventoryCoverage)
			}
			files, err := r.Files()
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"example.invalid", "private-main", "private-action", "private-extra", "nested/go.mod", record.TargetBefore.Root} {
				if bytes.Contains(files.PortableJSON, []byte(private)) || bytes.Contains(files.Summary, []byte(private)) {
					t.Fatalf("private declaration leaked: %s", private)
				}
			}
			if tc.name == "empty" {
				if len(r.InventoryCoverage.Evidence) < 3 {
					t.Fatal("manifest/native/export evidence references lost")
				}
				if output := os.Getenv("PAO_GO_DECLARATION_SCHEMA_OUTPUT"); output != "" {
					encoded, err := plan.LockJSON(lock)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(output, "empty-go-plan.json"), encoded, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(output, "empty-go-report.json"), files.PortableJSON, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestEmptyGoDeclarationEvidenceCannotSurviveTamperingOrFailure(t *testing.T) {
	for _, mutation := range []string{"plan", "snapshot", "failed-syft"} {
		t.Run(mutation, func(t *testing.T) {
			root, lock, record, catalog := syntheticDependencyContentsRun(t, map[string]string{"go.mod": emptyGoManifest}, syftEmptyGo)
			switch mutation {
			case "plan":
				lock.Detected.EmptyGoModuleHashes[0] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "snapshot":
				record.TargetBefore.Files[0].GoModDeclaration = ""
			case "failed-syft":
				for i := range record.Executions {
					if record.Executions[i].AdapterID == "syft" {
						record.Executions[i].Status = runner.Failed
						record.Executions[i].Coverage.Status = runner.Failed
					}
				}
			}
			r := Build(root, lock, record, catalog, false)
			if r.InventoryCoverage.Adequate || len(r.InventoryCoverage.VerifiedEmptyDeclaredEcosystems) > 0 || r.AnalysisCoverageComplete {
				t.Fatalf("invalid evidence upgraded coverage: %+v", r.InventoryCoverage)
			}
		})
	}
}

func TestOptionalCycloneDXComponentsStillMustMatchNativeInventory(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	if !consistentInventoryExport(nil, data) {
		t.Fatal("valid omitted empty components rejected")
	}
	if consistentInventoryExport([]nativeItem{{Category: "inventory", Component: "synthetic", ComponentVersion: "1"}}, data) {
		t.Fatal("omitted components erased native package")
	}
	if _, err := inspectCycloneDX(data); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":null}`)); err == nil {
		t.Fatal("present null components accepted")
	}
}
