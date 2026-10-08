package scancode

import "testing"

func TestResultStatusDoesNotMakeLegalVerdicts(t *testing.T) {
	if result := ParseResult([]byte(`{"files":[{"path":"LICENSE","detected_license_expression":"LicenseRef-Company"}]}`)); result.Status != "SUCCEEDED" {
		t.Fatalf("license observation was not retained: %#v", result)
	}
	if result := ParseResult([]byte(`{"incomplete":true}`)); result.Status != "PARTIAL" {
		t.Fatalf("incomplete coverage was not retained: %#v", result)
	}
	if result := ParseResult([]byte(`not-json`)); result.Status != "FAILED" {
		t.Fatalf("malformed output passed: %#v", result)
	}
}
