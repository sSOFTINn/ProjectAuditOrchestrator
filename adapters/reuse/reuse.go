// Package reuse extracts exact license expressions from the constrained synthetic REUSE JSON contract.
package reuse

import (
	"encoding/json"
	"fmt"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/license"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type document struct {
	Licenses []struct {
		Path       string `json:"path"`
		Expression string `json:"spdx_expression"`
	} `json:"licenses"`
	Incomplete bool   `json:"incomplete"`
	Error      string `json:"error"`
}

// ParseResult reports a synthetic REUSE execution outcome; observations still
// require a separate manual legal review.
func ParseResult(raw []byte) adapter.ParsedResult {
	var parsed document
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return adapter.ParsedResult{Status: "FAILED", Reason: "malformed REUSE JSON"}
	}
	if parsed.Error != "" {
		return adapter.ParsedResult{Status: "FAILED", Reason: "upstream scanner reported failure"}
	}
	if parsed.Incomplete {
		return adapter.ParsedResult{Status: "PARTIAL", Reason: "scanner reported incomplete coverage"}
	}
	for _, item := range parsed.Licenses {
		if item.Path != "" && item.Expression != "" {
			return adapter.ParsedResult{Status: "SUCCEEDED"}
		}
	}
	return adapter.ParsedResult{Status: "NO_FINDINGS"}
}

func ParseObservations(raw []byte, evidenceRef string) ([]license.Observation, error) {
	var document document
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("malformed REUSE JSON: %w", err)
	}
	if document.Error != "" {
		return nil, fmt.Errorf("REUSE reported failure")
	}
	observations := make([]license.Observation, 0)
	for _, item := range document.Licenses {
		if item.Path == "" || item.Expression == "" {
			continue
		}
		observations = append(observations, license.Observation{ComponentID: item.Path, SPDXExpression: item.Expression, EvidenceRefs: []string{evidenceRef}, Status: license.StatusObserved})
	}
	return observations, nil
}
