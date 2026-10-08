// Package grype parses the constrained synthetic Grype JSON contract.
package grype

import (
	"encoding/json"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func Parse(raw []byte) adapter.ParsedResult {
	var document struct {
		Matches    []json.RawMessage `json:"matches"`
		Incomplete bool              `json:"incomplete"`
		Error      string            `json:"error"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed Grype JSON"}
	}
	if document.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if document.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	if len(document.Matches) == 0 {
		return adapter.ParsedResult{Status: "NO_FINDINGS"}
	}
	return adapter.ParsedResult{Status: "SUCCEEDED"}
}
