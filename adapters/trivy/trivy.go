// Package trivy parses the constrained synthetic Trivy filesystem/config output.
package trivy

import (
	"encoding/json"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func Parse(raw []byte) adapter.ParsedResult {
	var document struct {
		Incomplete bool `json:"incomplete"`
		Results    []struct {
			Class string            `json:"Class"`
			Type  string            `json:"Type"`
			Items []json.RawMessage `json:"Misconfigurations"`
		} `json:"Results"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed Trivy JSON"}
	}
	if document.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if document.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	for _, result := range document.Results {
		if result.Class == "config" || result.Type == "config" {
			if len(result.Items) == 0 {
				continue
			}
			return adapter.ParsedResult{Status: "SUCCEEDED"}
		}
	}
	return adapter.ParsedResult{Status: "NO_FINDINGS"}
}
