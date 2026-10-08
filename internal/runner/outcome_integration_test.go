package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func TestNonPassOutcomeFixturesRemainExplicitAndEvidenceBacked(t *testing.T) {
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	malformed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scanner-outputs", "syft", "malformed.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.PutRaw("application/json", malformed, "exec-malformed")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		status    string
		execution ToolExecution
	}{
		{"unavailable", Unavailable, fixtureExecution(Unavailable)},
		{"malformed", Failed, ToolExecution{ID: "exec-malformed", PlanDigest: recordDigest, AdapterID: "syft", ToolID: "syft", ConfigDigest: recordDigest, Status: Failed, Coverage: toolchain.Coverage{ToolID: "syft", Capability: "inventory", Status: Failed, Reason: "malformed scanner output"}, RawArtifacts: []artifact.RawArtifact{raw}}},
		{"timed-out", TimedOut, fixtureExecution(TimedOut)},
		{"isolation-mismatch", PolicyBlocked, fixtureExecution(PolicyBlocked)},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			record := Record{Version: RunRecordVersion, PlanDigest: recordDigest, TargetBefore: target.Snapshot{TargetID: "sha256:target"}, TargetAfter: target.Snapshot{TargetID: "sha256:target"}, Executions: []ToolExecution{fixture.execution}}
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
			if record.Executions[0].Status != fixture.status || record.Executions[0].Status == Succeeded || record.Executions[0].Status == NoFindings {
				t.Fatalf("non-pass outcome was not explicit: %#v", record.Executions[0])
			}
		})
	}
}
