// Package opengrep parses the constrained synthetic static-analysis output.
package opengrep

import (
	"encoding/json"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

// Parse maps only the declared local rule-pack result contract. It never runs
// a target program and does not infer findings from scanner diagnostics.
func Parse(raw []byte) adapter.ParsedResult {
	var document struct {
		Results    []json.RawMessage `json:"results"`
		Incomplete bool              `json:"incomplete"`
		Error      string            `json:"error"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed Opengrep JSON"}
	}
	if document.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if document.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	if len(document.Results) == 0 {
		return adapter.ParsedResult{Status: "NO_FINDINGS"}
	}
	return adapter.ParsedResult{Status: "SUCCEEDED"}
}
