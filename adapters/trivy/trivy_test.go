package trivy

import "testing"

func TestTrivyParserIsLimitedToConfigCoverage(t *testing.T) {
	if result := Parse([]byte(`{"Results":[{"Class":"config","Misconfigurations":[{"ID":"SYNTHETIC"}]}]}`)); result.Status != "SUCCEEDED" {
		t.Fatalf("config finding was lost: %#v", result)
	}
	if result := Parse([]byte(`{"Results":[{"Class":"license","Misconfigurations":[{"ID":"SYNTHETIC"}]}]}`)); result.Status != "NO_FINDINGS" {
		t.Fatalf("overlapping module was treated as authoritative: %#v", result)
	}
	if result := Parse([]byte(`{"incomplete":true}`)); result.Status != "PARTIAL" {
		t.Fatalf("incomplete coverage was not retained: %#v", result)
	}
	if result := Parse([]byte(`not-json`)); result.Status != "FAILED" {
		t.Fatalf("malformed output passed: %#v", result)
	}
}
