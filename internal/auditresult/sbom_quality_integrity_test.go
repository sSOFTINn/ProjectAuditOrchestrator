package auditresult

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func TestSBOMQualityRejectsUntrustedLineageAndIncompleteCapture(t *testing.T) {
	for _, mode := range []string{"foreign-input-execution", "failed-syft", "unknown-syft-tool", "truncated-syft", "truncated-quality", "partial-quality", "failed-quality", "invalid-run", "three-owners"} {
		t.Run(mode, func(t *testing.T) {
			root, lock, record, catalog := syntheticRun(t, nil)
			var syft, quality *runner.ToolExecution
			for i := range record.Executions {
				switch record.Executions[i].AdapterID {
				case "syft":
					syft = &record.Executions[i]
				case "sbomqs":
					quality = &record.Executions[i]
				}
			}
			switch mode {
			case "foreign-input-execution":
				quality.InputArtifact.ExecutionID = "foreign-execution"
			case "failed-syft":
				syft.Status, syft.Coverage.Status = runner.Failed, runner.Failed
			case "unknown-syft-tool":
				syft.ToolDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "truncated-syft":
				syft.StdoutTruncated = true
			case "truncated-quality":
				quality.StdoutTruncated = true
			case "partial-quality":
				quality.Status, quality.Coverage.Status = runner.Partial, runner.Partial
			case "failed-quality":
				quality.Status, quality.Coverage.Status = runner.Failed, runner.Failed
			case "invalid-run":
				record.TargetAfter.Complete = false
			case "three-owners":
				// Identical bytes may be claimed by multiple executions; that must
				// never make an ambiguous reference uniquely owned again.
				input := *quality.InputArtifact
				for _, id := range []string{"reuse", "zizmor"} {
					for i := range record.Executions {
						e := &record.Executions[i]
						if e.AdapterID == id {
							ref := input
							ref.ExecutionID = e.ID
							e.RawArtifacts = append(e.RawArtifacts, ref)
						}
					}
				}
				for i := range record.Executions {
					if record.Executions[i].AdapterID == "syft" {
						last := len(record.Executions) - 1
						record.Executions[i], record.Executions[last] = record.Executions[last], record.Executions[i]
						break
					}
				}
			}
			result := Build(root, lock, record, catalog, false)
			if result.CoverageComplete || len(result.SBOMQuality) != 0 || len(result.Portable().SBOMQualityScores) != 0 {
				t.Fatalf("untrusted quality was accepted: status=%s observations=%#v", result.Status, result.SBOMQuality)
			}
		})
	}
}
