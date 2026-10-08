// Package gitleaks projects synthetic secret findings into a no-secret portable form.
package gitleaks

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type Finding struct {
	RuleID   string `json:"rule_id"`
	Location string `json:"location"`
	Redacted bool   `json:"redacted"`
}

// ParseResult converts the constrained output to an execution outcome without
// exposing raw secret data. Call Parse when the caller needs the portable findings.
func ParseResult(raw []byte) adapter.ParsedResult {
	var envelope struct {
		Incomplete bool   `json:"incomplete"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed Gitleaks JSON"}
	}
	if envelope.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if envelope.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	findings, err := Parse(raw)
	if err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: err.Error()}
	}
	if len(findings) == 0 {
		return adapter.ParsedResult{Status: "NO_FINDINGS"}
	}
	return adapter.ParsedResult{Status: "SUCCEEDED"}
}

// Parse never returns scanner-controlled secret text, commit messages, URLs or raw evidence refs.
func Parse(raw []byte) ([]Finding, error) {
	var document struct {
		Findings []struct {
			RuleID   string `json:"RuleID"`
			File     string `json:"File"`
			Secret   string `json:"Secret"`
			Redacted bool   `json:"Redacted"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, errors.New("malformed Gitleaks JSON")
	}
	result := make([]Finding, 0, len(document.Findings))
	for _, finding := range document.Findings {
		if finding.RuleID == "" || finding.File == "" || strings.HasPrefix(finding.File, "/") || strings.Contains(finding.File, "..") || (finding.Secret != "" && !finding.Redacted) {
			return nil, errors.New("unsafe or unredacted Gitleaks finding")
		}
		result = append(result, Finding{RuleID: finding.RuleID, Location: strings.ReplaceAll(finding.File, "\\", "/"), Redacted: finding.Redacted})
	}
	return result, nil
}
