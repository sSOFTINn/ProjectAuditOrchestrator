package auditresult

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
)

// Synthetic projections of the fields consumed from upstream Syft 1.57.0:
// schema/json/schema-16.1.13.json and syft/configuration_audit_trail.go.
// The upstream CycloneDX encoder still defaults to 1.7. These are not live
// scanner acceptance evidence and contain no copied target data.
const syft1570Inventory = `{"schema":{"version":"16.1.13"},"descriptor":{"name":"syft","version":"1.57.0","configuration":{"catalogers":{"used":["go-module-file-cataloger"]}}},"artifacts":[{"id":"synthetic-package","name":"example.invalid/synthetic","version":"v1.2.3","type":"go-module","purl":"pkg:golang/example.invalid/synthetic@v1.2.3","foundBy":"go-module-file-cataloger","locations":[{"path":"/pao/target/private.tar","accessPath":"/pao/target/private.tar!/go.mod","fullPath":"/pao/target/private.tar!/go.mod","annotations":{"evidence":"primary","private":"PAO_SYNTHETIC_PRIVATE_ANNOTATION"}}],"metadata":{"h1Digest":"synthetic","goCompiledVersion":""}}],"files":[{"id":"synthetic-file","location":{"path":"/pao/target/private-bin"},"executable":{"format":"elf","hasExports":false,"hasEntrypoint":true,"importedLibraries":[],"identifiers":[{"type":"gnu-build-id","value":"PAO_SYNTHETIC_PRIVATE_BUILD_ID"}]}}]}`

const syft1570EmptyGo = `{"schema":{"version":"16.1.13"},"descriptor":{"name":"syft","version":"1.57.0","configuration":{"catalogers":{"used":["go-module-file-cataloger"]}}},"artifacts":[]}`

func TestSyft1570NativeAndCycloneDXProjection(t *testing.T) {
	p := parseNative("syft", []byte(syft1570Inventory))
	if p.Status != "PARSED" || len(p.Reasons) != 0 || len(p.Items) != 1 || !p.GoModuleFileCatalogerUsed {
		t.Fatalf("current Syft inventory contract rejected: %#v", p)
	}
	item := p.Items[0]
	if item.Component != "example.invalid/synthetic" || item.ComponentVersion != "v1.2.3" || item.ComponentType != "go-module" || item.PURL != "pkg:golang/example.invalid/synthetic@v1.2.3" {
		t.Fatalf("current Syft inventory identity changed: %#v", item)
	}
	projected, err := json.Marshal(p.Items)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE_ANNOTATION", "PRIVATE_BUILD_ID", "private.tar", "private-bin"} {
		if bytes.Contains(projected, []byte(private)) {
			t.Fatalf("unconsumed Syft metadata entered the projection: %s", private)
		}
	}
	const cdx = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"library","name":"example.invalid/synthetic","version":"v1.2.3","purl":"pkg:golang/example.invalid/synthetic@v1.2.3","licenses":[{"license":{"id":"MIT"}}],"supplier":{"name":"synthetic-vendor"}}]}`
	if !consistentInventoryExport(p.Items, []byte(cdx)) {
		t.Fatal("CycloneDX 1.7 lost the exact native package identity")
	}
	if consistentInventoryExport(p.Items, []byte(strings.ReplaceAll(cdx, "v1.2.3", "v9.9.9"))) {
		t.Fatal("a changed CycloneDX package was accepted")
	}
	if quality, err := inspectCycloneDX([]byte(cdx)); err != nil || quality.totalMissing() != 0 {
		t.Fatalf("CycloneDX 1.7 completeness projection changed: %#v %v", quality, err)
	}
}

func TestSyft1570EmptyGoStillRequiresCatalogerAndMatchingExport(t *testing.T) {
	for _, tc := range []struct {
		name, native, cdx string
		adequate          bool
	}{
		{"empty", syft1570EmptyGo, `{"bomFormat":"CycloneDX","specVersion":"1.7"}`, true},
		{"notes", strings.Replace(syft1570EmptyGo, `"configuration":{`, `"configuration":{"notes":["synthetic incomplete scan"],`, 1), `{"bomFormat":"CycloneDX","specVersion":"1.7"}`, false},
		{"absent-cataloger", strings.Replace(syft1570EmptyGo, `"go-module-file-cataloger"`, `"different-cataloger"`, 1), `{"bomFormat":"CycloneDX","specVersion":"1.7"}`, false},
		{"malformed-cataloger", strings.Replace(syft1570EmptyGo, `"go-module-file-cataloger"`, `"go-module-file-cataloger",null`, 1), `{"bomFormat":"CycloneDX","specVersion":"1.7"}`, false},
		{"duplicate-cataloger", strings.Replace(syft1570EmptyGo, `"go-module-file-cataloger"`, `"go-module-file-cataloger","go-module-file-cataloger"`, 1), `{"bomFormat":"CycloneDX","specVersion":"1.7"}`, false},
		{"export-extra-package", syft1570EmptyGo, `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":"private-extra","version":"1","purl":"pkg:golang/private-extra@1"}]}`, false},
		{"export-null", syft1570EmptyGo, `{"bomFormat":"CycloneDX","specVersion":"1.7","components":null}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, lock, record, catalog := syntheticDependencyContentsRun(t, map[string]string{"go.mod": emptyGoManifest}, tc.native)
			store, err := artifact.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := store.PutRaw("application/vnd.cyclonedx+json", []byte(tc.cdx), "synthetic-syft")
			if err != nil {
				t.Fatal(err)
			}
			for i := range record.Executions {
				switch record.Executions[i].AdapterID {
				case "syft":
					record.Executions[i].RawArtifacts[1] = ref
				case "sbomqs":
					record.Executions[i].InputArtifact = &ref
				}
			}
			result := Build(root, lock, record, catalog, false)
			if result.InventoryCoverage.Adequate != tc.adequate || result.AnalysisCoverageComplete != tc.adequate {
				t.Fatalf("current empty-Go evidence changed coverage: %+v; reasons=%v", result.InventoryCoverage, result.Reasons)
			}
			if tc.adequate && (result.Status != "REVIEW_REQUIRED" || len(result.InventoryCoverage.VerifiedEmptyDeclaredEcosystems) != 1 || containsString(result.InventoryCoverage.ObservedEcosystems, "Go")) {
				t.Fatal("verified empty declaration became a scanner observation or approval")
			}
			if !tc.adequate && len(result.InventoryCoverage.VerifiedEmptyDeclaredEcosystems) != 0 {
				t.Fatal("incomplete evidence retained a verified empty declaration")
			}
		})
	}
}
