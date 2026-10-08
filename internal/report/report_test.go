package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/policy"
)

func reportInput() Input {
	finding := normalize.Finding{Version: normalize.SchemaVersion, FindingID: "finding-1", StableFingerprint: normalize.Fingerprint("fixture"), Category: "secret", Title: "Authorization: Bearer PAO_SYNTHETIC_SECRET_UNIT_TEST | injected\nrow", Description: "cookie=fixture; contact fixture@example.test; private key", Status: "OPEN", Severity: "HIGH", Confidence: "HIGH", ScannerID: "fixture", TargetID: "sha256:fixture", EvidenceRefs: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, RawResultRef: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ToolExecutionID: "exec-1"}
	decision := policy.Decision{ID: "decision-1", Verdict: "BLOCKED", PolicyDigest: "sha256:policy", InputDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234", DecisionDigest: "sha256:decision"}
	return Input{Findings: []normalize.Finding{finding}, Decision: decision, AsOf: time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)}
}

func TestPortableReportsRedactSecretsAndPreserveFindingID(t *testing.T) {
	input := reportInput()
	renderers := []struct {
		name       string
		structured bool
		render     func(Input) ([]byte, error)
	}{
		{"jsonl", false, JSONL},
		{"markdown", false, Markdown},
		{"sarif", true, SARIF},
		{"cyclonedx", true, CycloneDX},
		{"spdx", true, SPDX},
	}
	for _, renderer := range renderers {
		output, err := renderer.render(input)
		if err != nil {
			t.Fatal(err)
		}
		text := string(output)
		if strings.Contains(text, "PAO_SYNTHETIC_SECRET_UNIT_TEST") || strings.Contains(text, "fixture@example.test") || strings.Contains(text, "Authorization: Bearer") || strings.Contains(text, "cookie=fixture") || !strings.Contains(text, "finding-1") {
			t.Fatalf("portable report leaked data or lost identity: %s", text)
		}
		if renderer.structured && !json.Valid(output) {
			t.Fatalf("structured report is invalid JSON: %s", output)
		}
	}
	markdown, err := Markdown(input)
	if err != nil || strings.Contains(string(markdown), "| injected\nrow") {
		t.Fatalf("markdown injection was not neutralized: %s %v", markdown, err)
	}
}
