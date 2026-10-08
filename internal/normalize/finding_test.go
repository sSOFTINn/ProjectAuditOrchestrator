package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenFindingHasCanonicalEvidenceAndStableEncoding(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "finding-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var finding Finding
	if err := json.Unmarshal(raw, &finding); err != nil {
		t.Fatal(err)
	}
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	first, err := CanonicalJSON(finding)
	if err != nil {
		t.Fatal(err)
	}
	finding.EvidenceRefs = []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	second, err := CanonicalJSON(finding)
	if err != nil || string(first) != string(second) {
		t.Fatalf("canonical finding encoding is not stable: %s %s %v", first, second, err)
	}
}

func TestFindingRejectsNonInfoWithoutEvidence(t *testing.T) {
	finding := Finding{Version: SchemaVersion, FindingID: "finding-1", StableFingerprint: Fingerprint("fixture"), Category: "vulnerability", Title: "fixture", Status: "OPEN", Severity: "HIGH", Confidence: "HIGH", ScannerID: "fixture", TargetID: "sha256:fixture", RawResultRef: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ToolExecutionID: "exec-1"}
	if err := finding.Validate(); err == nil {
		t.Fatal("reportable finding without evidence was accepted")
	}
}

func TestSchemaMatchesRuntimeRequiredEvidenceContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "finding-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"version", "finding_id", "tool_execution_id", "raw_result_ref", "evidence_refs"} {
		found := false
		for _, required := range schema.Required {
			found = found || required == name
		}
		if !found || schema.Properties[name] == nil {
			t.Fatalf("schema does not require runtime field %q", name)
		}
	}
	if schema.AdditionalProperties || schema.Properties["correlation_group_id"] == nil || schema.Properties["conflict_group_id"] != nil {
		t.Fatalf("schema is not aligned with Finding: %#v", schema.Properties)
	}
}
