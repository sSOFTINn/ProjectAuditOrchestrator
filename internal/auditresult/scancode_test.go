package auditresult

import (
	"encoding/json"
	"strings"
	"testing"
)

const scanCodePackagesFixture = `{"headers":[{"tool_name":"scancode-toolkit","output_format_version":"4.1.0"}],"files":[{"path":"demo/go.mod","type":"file","package_data":[{"type":"golang","namespace":"example.invalid","name":"demo","purl":"pkg:golang/example.invalid/demo","version":null,"declared_license_expression_spdx":"MIT OR Apache-2.0","dependencies":[{"purl":"pkg:golang/example.invalid/dep@v1.0","extracted_requirement":"v1.0","scope":"require","is_runtime":true,"is_optional":false,"resolved_package":{}}]}]}],"packages":[{"type":"golang","namespace":"example.invalid","name":"demo","purl":"pkg:golang/example.invalid/demo","package_uid":"pkg:golang/example.invalid/demo?uuid=synthetic","datafile_paths":["demo/go.mod"],"datasource_ids":["go_mod"]}],"dependencies":[{"purl":"pkg:golang/example.invalid/dep@v1.0","extracted_requirement":"v1.0","datafile_path":"demo/go.mod","for_package_uid":"pkg:golang/example.invalid/demo?uuid=synthetic","dependency_uid":"synthetic-dependency"}]}`

func TestScanCodeProjectsPackagesWithoutMergingNativeOrigins(t *testing.T) {
	p := parseNative("scancode", []byte(scanCodePackagesFixture))
	if p.Status != "PARSED" {
		t.Fatalf("%#v", p)
	}
	inventories := map[string]nativeItem{}
	licenses := 0
	for _, i := range p.Items {
		if i.Category == "inventory" {
			inventories[i.SourcePointer] = i
		}
		if i.Category == "license" {
			licenses++
		}
	}
	if len(inventories) != 4 || licenses != 3 {
		t.Fatalf("lost records: %#v", p)
	}
	if i := inventories["/files/0/package_data/0"]; i.Component != "demo" || i.ComponentNamespace != "example.invalid" || i.ComponentVersion != "" {
		t.Fatal(i)
	}
	if i := inventories["/files/0/package_data/0/dependencies/0"]; i.PURL != "pkg:golang/example.invalid/dep@v1.0" || i.Requirement != "v1.0" || i.ComponentVersion != "" || i.IsOptional == nil || *i.IsOptional {
		t.Fatal(i)
	}
	if i := inventories["/dependencies/0"]; i.ForPackageUID == "" || i.DependencyUID == "" || i.Path != "demo/go.mod" {
		t.Fatal(i)
	}
}

func TestScanCodeMalformedPackageFieldsRemainPartial(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(scanCodePackagesFixture, `"package_data":[{`, `"package_data":[5,{`, 1),
		strings.Replace(scanCodePackagesFixture, `"is_runtime":true`, `"is_runtime":"true"`, 1),
		strings.Replace(scanCodePackagesFixture, `"version":null`, `"version":123`, 1),
		strings.Replace(scanCodePackagesFixture, `"datafile_paths":["demo/go.mod"]`, `"datafile_paths":{}`, 1),
		strings.Replace(scanCodePackagesFixture, `"resolved_package":{}`, `"resolved_package":{"something":"unsupported"}`, 1),
		strings.Replace(scanCodePackagesFixture, `"output_format_version":"4.1.0"`, `"output_format_version":"99.0"`, 1),
		`{"headers":[{"tool_name":"scancode-toolkit"}],"files":[{"path":"demo","type":"directory","scan_errors":["unreadable"]}]}`,
	} {
		if p := parseNative("scancode", []byte(raw)); p.Status != "PARTIAL" {
			t.Fatalf("accepted malformed data: %s", raw)
		}
	}
}

func TestScanCodeDoesNotCopyPartyTextOrLeakPackageMetadataToPortable(t *testing.T) {
	raw := strings.Replace(scanCodePackagesFixture, `"version":null`, `"version":null,"parties":[{"name":"PRIVATE_AUTHOR"}],"description":"PRIVATE_DESCRIPTION","notice_text":"PRIVATE_NOTICE"`, 1)
	p := parseNative("scancode", []byte(raw))
	encoded, _ := json.Marshal(p.Items)
	if strings.Contains(string(encoded), "PRIVATE_") {
		t.Fatal("copied uncontrolled native text")
	}
	r := Result{Status: "REVIEW_REQUIRED"}
	for _, i := range p.Items {
		r.Observations = append(r.Observations, Observation{Native: i})
	}
	portable, _ := json.Marshal(r.Portable())
	for _, s := range []string{"example.invalid", "demo/go.mod", "synthetic-dependency", "PRIVATE_"} {
		if strings.Contains(string(portable), s) {
			t.Fatal("private package metadata escaped")
		}
	}
}

func TestScanCodePackageProvenanceSurvivesEvidenceAggregation(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, map[string]string{"scancode": scanCodePackagesFixture})
	r := Build(root, lock, record, catalog, false)
	if r.Status != "REVIEW_REQUIRED" || !r.CoverageComplete {
		t.Fatalf("unexpected result: %#v", r)
	}
	count := 0
	for _, o := range r.Observations {
		if o.Scanner != "scancode" {
			continue
		}
		count++
		if o.Evidence == "" || o.ExecutionID == "" || o.ConfigDigest == "" || o.Native.SourcePointer == "" {
			t.Fatal("missing provenance")
		}
	}
	if count != 7 {
		t.Fatalf("observations: %d", count)
	}
	for _, f := range r.Findings {
		if f.Status != "MANUAL_REVIEW" {
			t.Fatal("automatic verdict")
		}
	}
}

func TestScanCodePackageLimitsAreExplicit(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 8193), "bad\u0000value"} {
		encoded, _ := json.Marshal(value)
		raw := strings.Replace(scanCodePackagesFixture, `"namespace":"example.invalid"`, `"namespace":`+string(encoded), 1)
		if p := parseNative("scancode", []byte(raw)); p.Status != "PARTIAL" {
			t.Fatal("unbounded metadata accepted")
		}
	}
	dep := `{"purl":"pkg:generic/demo"}`
	for n := 0; n < 6; n++ {
		dep = `{"purl":"pkg:generic/demo","resolved_package":{"type":"generic","name":"demo","dependencies":[` + dep + `]}}`
	}
	raw := `{"headers":[{"tool_name":"scancode-toolkit"}],"files":[],"dependencies":[` + dep + `]}`
	if p := parseNative("scancode", []byte(raw)); p.Status != "PARTIAL" {
		t.Fatal("unbounded resolved-package traversal")
	}
	raw = `{"headers":[{"tool_name":"scancode-toolkit"}],"files":[],"dependencies":[` + strings.TrimSuffix(strings.Repeat(`{"purl":"pkg:generic/demo"},`, maxItems+1), ",") + `]}`
	p := parseNative("scancode", []byte(raw))
	if p.Status != "PARTIAL" || len(p.Items) != maxItems {
		t.Fatal("unbounded record count")
	}
}
