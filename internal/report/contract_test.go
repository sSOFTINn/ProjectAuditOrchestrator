package report

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
)

// These regression checks cover the emitted subset of SARIF 2.1.0, CycloneDX
// 1.5 and SPDX 2.3, not complete upstream JSON Schema validation. Release schema
// validation must also run the pinned offline schemas against actual outputs.

func decodeContract(t *testing.T, raw []byte, dst any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("structured export contains trailing JSON")
	}
}

func TestCycloneDXSerialNumberUsesStableRFCUUID(t *testing.T) {
	// Version 5 and the RFC variant bits are checked in addition to the upstream
	// CycloneDX 1.5 serialNumber pattern (8-4-4-4-12 lowercase hex groups).
	pattern := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	serial := func(input Input) string {
		t.Helper()
		raw, err := CycloneDX(input)
		if err != nil {
			t.Fatal(err)
		}
		var output struct {
			SerialNumber string `json:"serialNumber"`
		}
		if err := json.Unmarshal(raw, &output); err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(output.SerialNumber) {
			t.Fatalf("serialNumber is not an RFC UUID v5: %q", output.SerialNumber)
		}
		return output.SerialNumber
	}
	input := reportInput()
	first := serial(input)
	if got := serial(input); got != first {
		t.Fatal("identical canonical input changed the UUID")
	}
	input.Decision.InputDigest = input.Decision.InputDigest[:len(input.Decision.InputDigest)-1] + "5"
	if got := serial(input); got == first {
		t.Fatal("a digest change after the first 128 bits did not change UUID")
	}
	for _, digest := range []string{"sha256:x", "unknown-format/" + strings.Repeat("x", 40)} {
		input.Decision.InputDigest = digest
		serial(input)
	}
}

func TestCycloneDXEmittedContract(t *testing.T) {
	for _, empty := range []bool{false, true} {
		input := reportInput()
		input.AsOf = input.AsOf.In(time.FixedZone("fixture", 3*60*60))
		if empty {
			input.Findings = nil
		}
		raw, err := CycloneDX(input)
		if err != nil {
			t.Fatal(err)
		}
		var output struct {
			BOMFormat    string `json:"bomFormat"`
			SpecVersion  string `json:"specVersion"`
			SerialNumber string `json:"serialNumber"`
			Version      int    `json:"version"`
			Metadata     struct {
				Timestamp string `json:"timestamp"`
				Component struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"component"`
			} `json:"metadata"`
			Vulnerabilities []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
			} `json:"vulnerabilities"`
		}
		decodeContract(t, raw, &output)
		if output.BOMFormat != "CycloneDX" || output.SpecVersion != "1.5" || output.Version < 1 || output.Metadata.Component.Type != "application" || output.Metadata.Component.Name == "" {
			t.Fatalf("invalid CycloneDX envelope: %s", raw)
		}
		stamp, err := time.Parse(time.RFC3339, output.Metadata.Timestamp)
		if err != nil || !stamp.Equal(input.AsOf) || !strings.HasSuffix(output.Metadata.Timestamp, "Z") {
			t.Fatalf("CycloneDX did not preserve UTC as-of time: %v", err)
		}
		if len(output.Vulnerabilities) != len(input.Findings) {
			t.Fatal("CycloneDX changed finding count")
		}
		for i, finding := range input.Findings {
			if output.Vulnerabilities[i].ID != finding.FindingID || output.Vulnerabilities[i].Description != "Canonical finding "+finding.FindingID {
				t.Fatal("CycloneDX lost canonical identity or exposed scanner text")
			}
		}
	}
}

func TestSARIFEmittedContract(t *testing.T) {
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "empty"} {
		t.Run(severity, func(t *testing.T) {
			input := reportInput()
			if severity == "empty" {
				input.Findings = nil
			} else {
				input.Findings[0].Severity = severity
			}
			raw, err := SARIF(input)
			if err != nil {
				t.Fatal(err)
			}
			var output struct {
				Version string `json:"version"`
				Schema  string `json:"$schema"`
				Runs    []struct {
					Tool struct {
						Driver struct {
							Name string `json:"name"`
						} `json:"driver"`
					} `json:"tool"`
					Results []struct {
						RuleID  string `json:"ruleId"`
						Level   string `json:"level"`
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
						PartialFingerprints map[string]string `json:"partialFingerprints"`
					} `json:"results"`
				} `json:"runs"`
			}
			decodeContract(t, raw, &output)
			if output.Version != "2.1.0" || output.Schema != "https://json.schemastore.org/sarif-2.1.0.json" || len(output.Runs) != 1 || output.Runs[0].Tool.Driver.Name != "PAO" {
				t.Fatal("invalid SARIF tool/version envelope")
			}
			results := output.Runs[0].Results
			if results == nil || len(results) != len(input.Findings) {
				t.Fatal("SARIF results must be an array preserving finding count")
			}
			for i, finding := range input.Findings {
				result := results[i]
				if result.RuleID != finding.ScannerID || result.Message.Text != "Canonical finding "+finding.FindingID || len(result.PartialFingerprints) != 2 || result.PartialFingerprints["pao/finding_id"] != finding.FindingID || result.PartialFingerprints["pao/stable_fingerprint"] != finding.StableFingerprint {
					t.Fatal("SARIF result lost canonical identifiers")
				}
				wantLevel := map[string]string{"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note", "UNKNOWN": "note"}[severity]
				if result.Level != wantLevel {
					t.Fatalf("SARIF severity mapping: got %q want %q", result.Level, wantLevel)
				}
			}
		})
	}
}

func TestSPDXEmittedContract(t *testing.T) {
	input := reportInput()
	raw, err := SPDX(input)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Version           string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Comment string `json:"comment"`
	}
	decodeContract(t, raw, &output)
	if output.Version != "SPDX-2.3" || output.DataLicense != "CC0-1.0" || output.SPDXID != "SPDXRef-DOCUMENT" || output.Name == "" || len(output.CreationInfo.Creators) != 1 || !strings.HasPrefix(output.CreationInfo.Creators[0], "Tool: ") {
		t.Fatal("invalid SPDX document-creation contract")
	}
	namespace, err := url.Parse(output.DocumentNamespace)
	if err != nil || !namespace.IsAbs() || namespace.Scheme != "https" || namespace.Host == "" || namespace.Fragment != "" {
		t.Fatalf("SPDX document namespace is not an absolute fragment-free URI: %v", err)
	}
	stamp, err := time.Parse(time.RFC3339, output.CreationInfo.Created)
	if err != nil || !stamp.Equal(input.AsOf) || !strings.HasSuffix(output.CreationInfo.Created, "Z") {
		t.Fatalf("SPDX did not preserve UTC as-of time: %v", err)
	}
	if !strings.Contains(output.Comment, "Verdict="+input.Decision.Verdict) || !strings.Contains(output.Comment, input.Findings[0].FindingID) {
		t.Fatal("SPDX comment lost decision or canonical finding identity")
	}
}

func TestJSONLPreservesPortableFieldsAndEmptyDocument(t *testing.T) {
	input := reportInput()
	raw, err := JSONL(input)
	if err != nil {
		t.Fatal(err)
	}
	var got PortableFinding
	decodeContract(t, raw, &got)
	finding := input.Findings[0]
	if got.FindingID != finding.FindingID || got.StableFingerprint != finding.StableFingerprint || got.Category != finding.Category || got.Status != finding.Status || got.Severity != finding.Severity || got.Confidence != finding.Confidence || got.ScannerID != finding.ScannerID || got.TargetID != finding.TargetID || got.EvidenceCount != len(finding.EvidenceRefs) {
		t.Fatal("JSONL changed portable finding fields")
	}
	input.Findings = nil
	if raw, err := JSONL(input); err != nil || len(raw) != 0 {
		t.Fatalf("empty JSONL report must contain no rows: %s %v", raw, err)
	}
}

func TestEveryRendererRejectsIncompleteCanonicalInput(t *testing.T) {
	for _, invalid := range []struct {
		name string
		edit func(*Input)
	}{
		{"missing as-of", func(input *Input) { input.AsOf = time.Time{} }},
		{"missing decision", func(input *Input) { input.Decision.DecisionDigest = "" }},
		{"unknown finding version", func(input *Input) { input.Findings[0].Version = normalize.SchemaVersion + "-future" }},
	} {
		for _, renderer := range []struct {
			name   string
			render func(Input) ([]byte, error)
		}{{"jsonl", JSONL}, {"markdown", Markdown}, {"sarif", SARIF}, {"cyclonedx", CycloneDX}, {"spdx", SPDX}} {
			t.Run(renderer.name+"/"+invalid.name, func(t *testing.T) {
				input := reportInput()
				invalid.edit(&input)
				if raw, err := renderer.render(input); err == nil || len(raw) != 0 {
					t.Fatal("renderer emitted an incomplete canonical report")
				}
			})
		}
	}
}
