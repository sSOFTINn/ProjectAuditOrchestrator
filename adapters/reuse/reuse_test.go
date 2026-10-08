package reuse

import "testing"

func TestResultStatusDoesNotMakeLegalVerdicts(t *testing.T) {
	if result := ParseResult([]byte(`{"licenses":[{"path":"LICENSE","spdx_expression":"MIT OR Apache-2.0"}]}`)); result.Status != "SUCCEEDED" {
		t.Fatalf("license observation was not retained: %#v", result)
	}
	if result := ParseResult([]byte(`{"incomplete":true}`)); result.Status != "PARTIAL" {
		t.Fatalf("incomplete coverage was not retained: %#v", result)
	}
	if result := ParseResult([]byte(`not-json`)); result.Status != "FAILED" {
		t.Fatalf("malformed output passed: %#v", result)
	}
}
