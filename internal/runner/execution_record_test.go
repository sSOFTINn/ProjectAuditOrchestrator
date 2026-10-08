package runner

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

const recordDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRecordRetainsEveryExplicitNonPassStatus(t *testing.T) {
	statuses := []string{Succeeded, NoFindings, Partial, Unavailable, Unsupported, TimedOut, Failed, PolicyBlocked}
	record := Record{Version: RunRecordVersion, PlanDigest: recordDigest, TargetBefore: target.Snapshot{TargetID: "sha256:target"}, TargetAfter: target.Snapshot{TargetID: "sha256:target"}}
	for index, status := range statuses {
		execution := fixtureExecution(status)
		execution.ID = "exec-" + string(rune('a'+index))
		if status == Succeeded || status == NoFindings || status == Partial {
			execution.RawArtifacts[0].ExecutionID = execution.ID
		}
		record.Executions = append(record.Executions, execution)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("explicit statuses were not retained: %v", err)
	}
}

func TestRecordRejectsTargetMutationAndFalseSuccess(t *testing.T) {
	record := Record{Version: RunRecordVersion, PlanDigest: recordDigest, TargetBefore: target.Snapshot{TargetID: "sha256:before"}, TargetAfter: target.Snapshot{TargetID: "sha256:after"}, Executions: []ToolExecution{fixtureExecution(Unavailable)}}
	if err := record.Validate(); err == nil {
		t.Fatal("target mutation was accepted")
	}
	record.TargetAfter.TargetID = record.TargetBefore.TargetID
	record.Executions[0].Coverage.Status = Succeeded
	if err := record.Validate(); err == nil {
		t.Fatal("unavailable execution was converted to success")
	}
}

func TestRecordRejectsMalformedPreparedStateDigest(t *testing.T) {
	execution := fixtureExecution(Unavailable)
	execution.StateDigest = "not-a-digest"
	if err := execution.Validate(); err == nil {
		t.Fatal("malformed prepared-state digest was accepted")
	}
}

func TestRecordRejectsMalformedProductionPrerequisiteDigest(t *testing.T) {
	for _, mutate := range []func(*ToolExecution){
		func(execution *ToolExecution) { execution.RuntimeDigest = "mutable:latest" },
		func(execution *ToolExecution) { execution.RulePackDigest = "not-a-digest" },
		func(execution *ToolExecution) { execution.LicenseDataDigest = "not-a-digest" },
	} {
		execution := fixtureExecution(Unavailable)
		mutate(&execution)
		if err := execution.Validate(); err == nil {
			t.Fatal("malformed production prerequisite digest was accepted")
		}
	}
}

func fixtureExecution(status string) ToolExecution {
	execution := ToolExecution{ID: "exec-a", PlanDigest: recordDigest, AdapterID: "fixture", ToolID: "fixture", ConfigDigest: recordDigest, Status: status, Coverage: toolchain.Coverage{ToolID: "fixture", Capability: "fixture", Status: status, Reason: "recorded fixture outcome"}}
	if status == Succeeded || status == NoFindings || status == Partial {
		execution.Sandbox = SandboxProperties{Isolation: StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}
		execution.RawArtifacts = []artifact.RawArtifact{{SHA256: recordDigest, Path: "raw/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExecutionID: execution.ID}}
	}
	return execution
}
