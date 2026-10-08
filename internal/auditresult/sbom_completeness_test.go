package auditresult

import (
	"encoding/json"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
)

func TestCycloneDXCompletenessIncludesNestedComponents(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"parent","version":"1","licenses":[{"license":{"id":"MIT"}}],"supplier":{"name":"vendor"},"components":[{"name":"child","components":[{"name":"  ","version":" ","supplier":{"name":" "}}]}]}]}`)
	got, err := inspectCycloneDX(raw)
	if err != nil || got.name != 1 || got.version != 2 || got.license != 2 || got.supplier != 2 {
		t.Fatalf("nested missing details lost: %+v %v", got, err)
	}
}

func TestMalformedCycloneDXDoesNotProduceQualityScore(t *testing.T) {
	for _, component := range []string{
		`{"name":42}`, `{"name":"demo","version":[]}`,
		`{"name":"demo","supplier":"vendor"}`, `{"name":"demo","supplier":{"name":false}}`,
		`{"name":"demo","licenses":"MIT"}`, `{"name":"demo","licenses":[{}]}`,
		`{"name":"demo","licenses":[{"license":null}]}`,
		`{"name":"demo","licenses":[{"expression":17}]}`,
		`{"name":"demo","components":{}}`, `{"name":"demo","components":[null]}`,
	} {
		t.Run(component, func(t *testing.T) {
			root, lock, record, catalog := syntheticRun(t, nil)
			store, err := artifact.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := store.PutRaw("application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[`+component+`]}`), "synthetic-syft")
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
			got := Build(root, lock, record, catalog, false)
			if got.CoverageComplete || len(got.SBOMQuality) != 0 || len(got.Portable().SBOMQualityScores) != 0 {
				t.Fatalf("malformed SBOM yielded a score: %+v", got.SBOMQuality)
			}
		})
	}
}

func TestCycloneDXCompletenessRejectsComponentLimit(t *testing.T) {
	components := make([]map[string]any, maxItems+1)
	for i := range components {
		components[i] = map[string]any{"name": "synthetic"}
	}
	raw, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCycloneDX(raw); err == nil {
		t.Fatal("component limit was ignored")
	}
}

func TestCycloneDXCompletenessDistinguishesAbsentAndPresentLicenseText(t *testing.T) {
	for _, tc := range []struct {
		licenses string
		missing  int
	}{
		{`[]`, 1},
		{`[{"license":{}}]`, 1},
		{`[{"license":{"id":"  "}}]`, 1},
		{`[{"expression":" "}]`, 1},
		{`[{"license":{"id":"MIT"}}]`, 0},
		{`[{"license":{"name":"Synthetic custom terms"}}]`, 0},
		{`[{"expression":"MIT OR Apache-2.0"}]`, 0},
	} {
		raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"synthetic","version":"1","supplier":{"name":"vendor"},"licenses":` + tc.licenses + `}]}`)
		got, err := inspectCycloneDX(raw)
		if err != nil || got.license != tc.missing || got.name != 0 || got.version != 0 || got.supplier != 0 {
			t.Fatalf("presence check for %s: %+v %v", tc.licenses, got, err)
		}
	}
}
