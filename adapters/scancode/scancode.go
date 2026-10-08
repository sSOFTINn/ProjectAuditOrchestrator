// Package scancode extracts exact license expressions from the constrained synthetic ScanCode JSON contract.
package scancode

import (
	"encoding/json"
	"fmt"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/license"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type document struct {
	Files []struct {
		Path       string `json:"path"`
		Expression string `json:"detected_license_expression"`
	} `json:"files"`
	Incomplete bool   `json:"incomplete"`
	Error      string `json:"error"`
}

// ParseResult reports a synthetic ScanCode execution outcome; license text is
// deliberately not used to make an automatic legal decision.
func ParseResult(raw []byte) adapter.ParsedResult {
	var parsed document
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed ScanCode JSON"}
	}
	if parsed.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if parsed.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	for _, file := range parsed.Files {
		if file.Path != "" && file.Expression != "" {
			return adapter.ParsedResult{Status: "SUCCEEDED"}
		}
	}
	return adapter.ParsedResult{Status: "NO_FINDINGS"}
}

func ParseObservations(raw []byte, evidenceRef string) ([]license.Observation, error) {
	var document document
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("malformed ScanCode JSON: %w", err)
	}
	if document.Error != "" {
		return nil, fmt.Errorf("ScanCode reported failure")
	}
	observations := make([]license.Observation, 0)
	for _, file := range document.Files {
		if file.Path == "" || file.Expression == "" {
			continue
		}
		observations = append(observations, license.Observation{ComponentID: file.Path, SPDXExpression: file.Expression, EvidenceRefs: []string{evidenceRef}, Status: license.StatusObserved})
	}
	return observations, nil
}
