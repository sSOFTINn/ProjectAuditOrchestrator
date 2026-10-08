package gitleaks

import (
	"strings"
	"testing"
)

func TestPortableFindingCannotLeakSecret(t *testing.T) {
	const secret = "PAO_SYNTHETIC_SECRET_MUST_NOT_ESCAPE"
	findings, err := Parse([]byte(`{"findings":[{"RuleID":"api-key","File":"src/config.go","Secret":"` + secret + `","Redacted":true}]}`))
	if err != nil || len(findings) != 1 {
		t.Fatalf("redacted finding was rejected: %#v %v", findings, err)
	}
	encoded := findings[0].RuleID + "|" + findings[0].Location
	if strings.Contains(encoded, secret) || !findings[0].Redacted {
		t.Fatalf("secret leaked into portable finding: %#v", findings[0])
	}
	if _, err := Parse([]byte(`{"findings":[{"RuleID":"api-key","File":"src/config.go","Secret":"` + secret + `","Redacted":false}]}`)); err == nil {
		t.Fatal("unredacted secret was accepted")
	}
}

func TestParserStatusRetainsIncompleteAndMalformedOutput(t *testing.T) {
	if result := ParseResult([]byte(`{"incomplete":true}`)); result.Status != "PARTIAL" {
		t.Fatalf("incomplete coverage was not retained: %#v", result)
	}
	if result := ParseResult([]byte(`not-json`)); result.Status != "FAILED" {
		t.Fatalf("malformed output passed: %#v", result)
	}
}
