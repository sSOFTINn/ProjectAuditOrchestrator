package opengrep

import "testing"

func TestParserPreservesExplicitFailures(t *testing.T) {
	if result := Parse([]byte(`{"results":[{"check_id":"synthetic.rule"}]}`)); result.Status != "SUCCEEDED" {
		t.Fatalf("finding was lost: %#v", result)
	}
	if result := Parse([]byte(`{"incomplete":true}`)); result.Status != "PARTIAL" {
		t.Fatalf("incomplete coverage was not retained: %#v", result)
	}
	if result := Parse([]byte(`not-json`)); result.Status != "FAILED" {
		t.Fatalf("malformed output passed: %#v", result)
	}
}
