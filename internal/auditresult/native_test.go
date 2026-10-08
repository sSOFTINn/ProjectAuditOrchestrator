package auditresult

import (
	"strings"
	"testing"
)

// All data below is synthetic; these are native wire shapes, not real audit output.
var nativeFixtures = map[string]string{
	"syft":        `{"schema":{"version":"16.1.3"},"artifacts":[{"name":"demo","version":"1.0","purl":"pkg:golang/demo@1.0"}]}`,
	"grype":       `{"matches":[{"vulnerability":{"id":"CVE-2099-10000","severity":"High","fix":{"versions":["2.0"]}},"artifact":{"name":"demo","version":"1.0","purl":"pkg:golang/demo@1.0"}}]}`,
	"osv-scanner": `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"demo","version":"1.0","ecosystem":"Go"},"vulnerabilities":[{"id":"CVE-2099-10000","database_specific":{"severity":"HIGH"}}]}]}]}`,
	"trivy":       `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-10000","PkgName":"demo","InstalledVersion":"1.0","FixedVersion":"2.0","Severity":"HIGH"}]}]}`,
	"gitleaks":    `[{"RuleID":"synthetic-key","File":"demo.txt","StartLine":3,"Secret":"PAO_SYNTHETIC_SECRET_TEST","Match":"must never be copied"}]`,
	"opengrep":    `{"results":[{"check_id":"synthetic.rule","path":"demo.py","start":{"line":2},"extra":{"severity":"ERROR","message":"private message","lines":"private code"}}],"errors":[],"paths":{"scanned":["demo.py"]}}`,
	"zizmor":      `[{"ident":"template-injection","determinations":{"confidence":"High","severity":"High"},"locations":[{"symbolic":{"key":{"Local":{"verbatim_path":".github/workflows/demo.yml"}}}}]}]`,
	"scancode":    `{"headers":[{"tool_name":"scancode-toolkit","errors":[]}],"files":[{"path":"demo.txt","type":"file","detected_license_expression_spdx":"MIT OR Apache-2.0","scan_errors":[]}]}`,
	"reuse":       `{"lint_version":"1.0","reuse_tool_version":"6.2.0","non_compliant":{"missing_licensing_info":["demo.txt"]},"files":[{"path":"demo.txt","spdx_expressions":[]}],"summary":{"compliant":false,"files_total":1}}`,
}

const qualityFixture = `{"files":[{"avg_score":8.5}]}`

func TestSyftUnknownNativeSchemaCannotBecomeCompleteInventory(t *testing.T) {
	for _, version := range []string{"1", "16.1.4", "16.1.11", "17.0.0", "future"} {
		raw := strings.Replace(nativeFixtures["syft"], "16.1.3", version, 1)
		parsed := parseNative("syft", []byte(raw))
		if parsed.Status != "UNSUPPORTED_FORMAT" || len(parsed.Items) != 0 || !strings.Contains(strings.Join(parsed.Reasons, ","), "UNSUPPORTED_NATIVE_SCHEMA") {
			t.Fatalf("unknown schema produced inventory: %#v", parsed)
		}
	}
}

func TestPinnedSyft1511NativeSchemaPreservesInventory(t *testing.T) {
	// The pinned upstream emits schema 16.1.10. Additional metadata must not
	// hide the package identity used by inventory completeness checks.
	const raw = `{"schema":{"version":"16.1.10"},"descriptor":{"name":"syft","version":"1.51.1"},"artifacts":[{"id":"synthetic-package","name":"golang.org/x/text","version":"v0.3.0","type":"go-module","purl":"pkg:golang/golang.org/x/text@v0.3.0","metadata":{"h1Digest":"synthetic","goCompiledVersion":""}}],"source":{"type":"directory"}}`
	p := parseNative("syft", []byte(raw))
	if p.Status != "PARSED" || len(p.Reasons) != 0 || len(p.Items) != 1 {
		t.Fatalf("pinned upstream inventory refused: %#v", p)
	}
	item := p.Items[0]
	if item.Component != "golang.org/x/text" || item.ComponentVersion != "v0.3.0" || item.ComponentType != "go-module" || item.PURL != "pkg:golang/golang.org/x/text@v0.3.0" {
		t.Fatalf("pinned upstream inventory lost package identity: %#v", item)
	}
}

func TestNativeNineFormats(t *testing.T) {
	for id, raw := range nativeFixtures {
		t.Run(id, func(t *testing.T) {
			p := parseNative(id, []byte(raw))
			if p.Status != "PARSED" || len(p.Items) == 0 {
				t.Fatalf("%s: %#v", id, p)
			}
			for _, item := range p.Items {
				if item.Severity == "" {
					t.Fatal("missing explicit severity")
				}
			}
		})
	}
}

func TestNativeRejectsMissingMalformedAndDuplicateFields(t *testing.T) {
	for id := range nativeFixtures {
		for _, raw := range []string{`{}`, `null`, `{"results":[]`, `{"matches":[],"matches":[{}]}`, `{"a":{"b":1,"b":2}}`, `[] []`} {
			p := parseNative(id, []byte(raw))
			if p.Status == "PARSED" {
				t.Fatalf("accepted %s %s", id, raw)
			}
		}
	}
	if p := parseNative("future-tool", []byte(`[]`)); p.Status != "UNSUPPORTED_FORMAT" {
		t.Fatal(p)
	}
}

func TestNativeExplicitEmptyAndPartial(t *testing.T) {
	for id, raw := range map[string]string{"syft": `{"schema":{"version":"16.1.3"},"artifacts":[]}`, "grype": `{"matches":[]}`, "osv-scanner": `{"results":[]}`, "trivy": `{"SchemaVersion":2,"Results":[]}`, "gitleaks": `[]`, "opengrep": `{"results":[],"errors":[]}`, "zizmor": `[]`, "scancode": `{"headers":[{"tool_name":"scancode-toolkit"}],"files":[]}`, "reuse": `{"lint_version":"1.0","files":[],"non_compliant":{},"summary":{"compliant":true,"files_total":0}}`} {
		p := parseNative(id, []byte(raw))
		if p.Status != "PARSED" || len(p.Items) != 0 {
			t.Fatalf("empty %s: %#v", id, p)
		}
	}
	for id, raw := range map[string]string{"opengrep": strings.Replace(nativeFixtures["opengrep"], `"errors":[]`, `"errors":[{"message":"failed"}]`, 1), "grype": `{"matches":[{"vulnerability":{"id":"CVE-2099-10000"},"artifact":{"name":"demo"}},{}]}`, "reuse": `{"lint_version":"1.0","files":[],"non_compliant":{"read_errors":["demo"]},"summary":{"compliant":false,"files_total":0}}`} {
		p := parseNative(id, []byte(raw))
		if p.Status == "PARSED" {
			t.Fatalf("partial accepted %s: %#v", id, p)
		}
	}
}

func TestTrivyOmittedEmptyResultsAndInvalidFields(t *testing.T) {
	// Trivy v0.74.0 omits an empty Results slice from its JSON report.
	const emptyReport = `{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ReportID":"synthetic","ArtifactName":"synthetic","ArtifactType":"filesystem"}`
	if p := parseNative("trivy", []byte(emptyReport)); p.Status != "PARSED" || len(p.Items) != 0 {
		t.Fatalf("valid omitted empty results were rejected: %#v", p)
	}
	for _, tc := range []struct {
		raw, reason string
	}{
		{`{"SchemaVersion":1}`, "UNSUPPORTED_SCHEMA_VERSION"},
		{`{"SchemaVersion":2,"Results":null}`, "INVALID_RESULT_FIELD"},
		{`{"SchemaVersion":2,"Results":{}}`, "INVALID_RESULT_FIELD"},
		{`{"SchemaVersion":2,"error":"scan failed"}`, "SCANNER_REPORTED_INCOMPLETE"},
	} {
		p := parseNative("trivy", []byte(tc.raw))
		if p.Status != "PARTIAL" || !strings.Contains(strings.Join(p.Reasons, ","), tc.reason) {
			t.Fatalf("invalid Trivy report accepted: %s %#v", tc.raw, p)
		}
	}
}

func TestMissingSeverityIsNotInventedAndNativeSecretsAreDropped(t *testing.T) {
	p := parseNative("gitleaks", []byte(nativeFixtures["gitleaks"]))
	if p.Items[0].Severity != "UNKNOWN" {
		t.Fatal(p)
	}
	p = parseNative("opengrep", []byte(nativeFixtures["opengrep"]))
	if p.Items[0].Severity != "UNKNOWN" || p.Items[0].NativeSeverity != "ERROR" {
		t.Fatal("ERROR is a rule level, not an approved security severity mapping")
	}
}

func TestDecoderLimitsAndWrongTypes(t *testing.T) {
	for _, raw := range []string{strings.Repeat("[", 65) + strings.Repeat("]", 65), `{"matches":null}`, `{"matches":[5]}`, `{"matches":""}`} {
		if p := parseNative("grype", []byte(raw)); p.Status == "PARSED" {
			t.Fatal("accepted invalid input")
		}
	}
	// Use the Trivy parser and a valid result class so this exercises the
	// malformed vulnerability collection, not a missing Grype field.
	raw := `{"SchemaVersion":2,"Results":[{"Target":"demo","Class":"lang-pkgs","Vulnerabilities":{}}]}`
	if p := parseNative("trivy", []byte(raw)); p.Status != "PARTIAL" || !strings.Contains(strings.Join(p.Reasons, ","), "INVALID_RESULT_FIELD") {
		t.Fatalf("Trivy accepted a non-array vulnerability collection: %#v", p)
	}
}

func TestNativeObservationLimitIsExplicit(t *testing.T) {
	item := `{"RuleID":"synthetic","File":"demo"}`
	raw := "[" + strings.TrimSuffix(strings.Repeat(item+",", maxItems+1), ",") + "]"
	p := parseNative("gitleaks", []byte(raw))
	if p.Status != "PARTIAL" || len(p.Items) != maxItems || !strings.Contains(strings.Join(p.Reasons, ","), "RESULT_LIMIT") {
		t.Fatal("missing explicit limit")
	}
	if p := parseNative("gitleaks", []byte{'[', 0xff, ']'}); p.Status != "MALFORMED_OUTPUT" {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestUnprojectedPackageResultsAndReadErrorsRemainPartial(t *testing.T) {
	for _, raw := range []string{
		`{"headers":[{"tool_name":"scancode-toolkit"}],"files":[{"path":"demo","type":"file","detected_license_expression_spdx":"MIT","package_data":[{"name":"demo"}]}]}`,
		`{"headers":[{"tool_name":"scancode-toolkit","errors":["failed"]}],"files":[]}`,
		`{"headers":[{"tool_name":"scancode-toolkit"}],"files":[],"packages":[{"name":"demo"}]}`,
	} {
		if p := parseNative("scancode", []byte(raw)); p.Status != "PARTIAL" {
			t.Fatal("silently ignored fields")
		}
	}
}
