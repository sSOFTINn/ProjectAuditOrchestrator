// Package zizmor parses the constrained synthetic workflow-security output.
package zizmor

import (
	"encoding/json"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

// Parse is called only after path-only planning found a workflow-related input.
func Parse(raw []byte) adapter.ParsedResult {
	var document struct {
		Findings   []json.RawMessage `json:"findings"`
		Incomplete bool              `json:"incomplete"`
		Error      string            `json:"error"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed zizmor JSON"}
	}
	if document.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if document.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	if len(document.Findings) == 0 {
		return adapter.ParsedResult{Status: "NO_FINDINGS"}
	}
	return adapter.ParsedResult{Status: "SUCCEEDED"}
}
