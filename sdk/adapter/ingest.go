package adapter

import (
	"errors"
	"fmt"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
)

type ParsedResult struct {
	Status string
	Reason string
}

type Parser func([]byte) ParsedResult

// IngestRawFirst preserves native evidence before a parser has any chance to reject it.
// A parser panic or unsupported status is recorded as FAILED, never converted to NO_FINDINGS.
func IngestRawFirst(store *artifact.Store, executionID, mediaType string, raw []byte, parser Parser) (artifact.RawArtifact, ParsedResult, error) {
	if parser == nil {
		return artifact.RawArtifact{}, ParsedResult{}, errors.New("adapter parser is required")
	}
	artifactRef, err := store.PutRaw(mediaType, raw, executionID)
	if err != nil {
		return artifact.RawArtifact{}, ParsedResult{}, err
	}
	result := safelyParse(parser, raw)
	if !knownOutcome(result.Status) {
		result = ParsedResult{Status: "FAILED", Reason: "adapter parser returned unsupported status"}
	}
	if err := store.Append(artifact.Event{Type: "ADAPTER_OUTPUT_PARSED", ExecutionID: executionID, Artifact: artifactRef.SHA256, Status: result.Status}); err != nil {
		return artifact.RawArtifact{}, ParsedResult{}, fmt.Errorf("record parser result: %w", err)
	}
	return artifactRef, result, nil
}

func safelyParse(parser Parser, raw []byte) (result ParsedResult) {
	defer func() {
		if recover() != nil {
			result = ParsedResult{Status: "FAILED", Reason: "adapter parser panicked"}
		}
	}()
	return parser(raw)
}

func knownOutcome(status string) bool {
	switch status {
	case "SUCCEEDED", "NO_FINDINGS", "PARTIAL", "FAILED":
		return true
	default:
		return false
	}
}
