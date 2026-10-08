package localaudit

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func TestUsableSyftSBOMRequiresSuccessfulExecutionAndOneArtifact(t *testing.T) {
	raw := artifact.RawArtifact{Path: "raw/sha256/fixture", MediaType: "application/vnd.syft+json"}
	for _, test := range []struct {
		name      string
		status    string
		artifacts []artifact.RawArtifact
		want      bool
	}{
		{name: "succeeded", status: runner.Succeeded, artifacts: []artifact.RawArtifact{raw}, want: true},
		{name: "no findings", status: runner.NoFindings, artifacts: []artifact.RawArtifact{raw}, want: false},
		{name: "partial", status: runner.Partial, artifacts: []artifact.RawArtifact{raw}, want: false},
		{name: "failed with diagnostic artifact", status: runner.Failed, artifacts: []artifact.RawArtifact{raw}, want: false},
		{name: "succeeded without artifact", status: runner.Succeeded, want: false},
		{name: "succeeded with wrong media type", status: runner.Succeeded, artifacts: []artifact.RawArtifact{{Path: raw.Path, MediaType: "application/octet-stream"}}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := usableSyftSBOM(runner.ToolExecution{Status: test.status, RawArtifacts: test.artifacts}); got != test.want {
				t.Fatalf("usableSyftSBOM() = %v, want %v", got, test.want)
			}
		})
	}
}
