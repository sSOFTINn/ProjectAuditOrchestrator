package runner

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

const RunRecordVersion = "pao.dev/run-record/v1alpha1"

const (
	Succeeded     = "SUCCEEDED"
	NoFindings    = "NO_FINDINGS"
	Partial       = "PARTIAL"
	Unavailable   = "UNAVAILABLE"
	Unsupported   = "UNSUPPORTED"
	TimedOut      = "TIMED_OUT"
	Failed        = "FAILED"
	PolicyBlocked = "POLICY_BLOCKED"
)

var sha256Reference = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ToolExecution is the immutable, host-owned lineage record for one adapter result.
// It models a result even when no process was allowed to launch, so unavailable and
// policy-blocked coverage cannot be mistaken for a clean audit.
type ToolExecution struct {
	ID                string                 `json:"id"`
	PlanDigest        string                 `json:"plan_digest"`
	ManifestDigest    string                 `json:"manifest_digest,omitempty"`
	AdapterID         string                 `json:"adapter_id"`
	ToolID            string                 `json:"tool_id"`
	ToolDigest        string                 `json:"tool_digest,omitempty"`
	ConfigDigest      string                 `json:"config_digest"`
	DatabaseDigest    string                 `json:"database_digest,omitempty"`
	StateDigest       string                 `json:"state_digest,omitempty"`
	RuntimeDigest     string                 `json:"runtime_digest,omitempty"`
	RulePackDigest    string                 `json:"rule_pack_digest,omitempty"`
	LicenseDataDigest string                 `json:"license_data_digest,omitempty"`
	Status            string                 `json:"status"`
	Sandbox           SandboxProperties      `json:"sandbox"`
	Coverage          toolchain.Coverage     `json:"coverage"`
	InputArtifact     *artifact.RawArtifact  `json:"input_artifact,omitempty"`
	RawArtifacts      []artifact.RawArtifact `json:"raw_artifacts,omitempty"`
	Diagnostics       []DiagnosticArtifact   `json:"diagnostics,omitempty"`
	DiagnosticCode    string                 `json:"diagnostic_code,omitempty"`
	ExitCode          *int                   `json:"exit_code,omitempty"`
	StdoutTruncated   bool                   `json:"stdout_truncated,omitempty"`
}

// Record joins the pre/post target snapshots, immutable plan identity and every
// adapter outcome. A mismatch makes the whole record incomplete rather than passable.
type Record struct {
	Producer     *buildinfo.Producer `json:"producer,omitempty"`
	Version      string              `json:"version"`
	PlanDigest   string              `json:"plan_digest"`
	TargetBefore target.Snapshot     `json:"target_before"`
	TargetAfter  target.Snapshot     `json:"target_after"`
	Executions   []ToolExecution     `json:"executions"`
}

func (r Record) Validate() error {
	if r.Producer != nil {
		if err := r.Producer.Validate(); err != nil {
			return err
		}
	}
	if r.Version != RunRecordVersion || !sha256Reference.MatchString(r.PlanDigest) {
		return errors.New("run record requires version and SHA-256 plan digest")
	}
	if r.TargetBefore.TargetID == "" || r.TargetAfter.TargetID == "" || r.TargetBefore.TargetID != r.TargetAfter.TargetID {
		return errors.New("target changed during run; record is incomplete")
	}
	if len(r.Executions) == 0 {
		return errors.New("run record requires at least one explicit execution outcome")
	}
	for _, execution := range r.Executions {
		if err := execution.Validate(); err != nil {
			return err
		}
		if execution.PlanDigest != r.PlanDigest {
			return errors.New("execution does not belong to run plan")
		}
	}
	return nil
}

func (e ToolExecution) Validate() error {
	if e.DiagnosticCode != "" && !KnownDiagnosticCode(e.DiagnosticCode) {
		return errors.New("unknown diagnostic code")
	}
	if e.ExitCode != nil && (*e.ExitCode < -1 || *e.ExitCode > 255) {
		return errors.New("invalid process exit code")
	}
	if len(e.Diagnostics) > 1 {
		return errors.New("duplicate diagnostic stream")
	}
	for _, d := range e.Diagnostics {
		r := d.Artifact
		if d.Stream != "stderr" || r.ExecutionID != e.ID || !sha256Reference.MatchString(r.SHA256) || r.Path != "raw/sha256/"+r.SHA256[7:] || r.Size < 0 || r.Size > MaxDiagnosticBytes || r.MediaType != "application/octet-stream" {
			return errors.New("invalid diagnostic evidence lineage")
		}
	}
	if e.ID == "" || e.AdapterID == "" || e.ToolID == "" || !sha256Reference.MatchString(e.PlanDigest) || !sha256Reference.MatchString(e.ConfigDigest) || (e.ManifestDigest != "" && !sha256Reference.MatchString(e.ManifestDigest)) {
		return errors.New("execution requires identity, adapter and plan/config digests")
	}
	if e.ToolDigest != "" && !sha256Reference.MatchString(e.ToolDigest) {
		return errors.New("execution tool digest must be a SHA-256 reference")
	}
	if e.DatabaseDigest != "" && !sha256Reference.MatchString(e.DatabaseDigest) {
		return errors.New("execution database digest must be a SHA-256 reference")
	}
	if e.StateDigest != "" && !sha256Reference.MatchString(e.StateDigest) {
		return errors.New("execution prepared-state digest must be a SHA-256 reference")
	}
	if e.RuntimeDigest != "" && !sha256Reference.MatchString(e.RuntimeDigest) {
		return errors.New("execution runtime digest must be a SHA-256 reference")
	}
	if e.RulePackDigest != "" && !sha256Reference.MatchString(e.RulePackDigest) {
		return errors.New("execution rule-pack digest must be a SHA-256 reference")
	}
	if e.LicenseDataDigest != "" && !sha256Reference.MatchString(e.LicenseDataDigest) {
		return errors.New("execution license-data digest must be a SHA-256 reference")
	}
	if !validExecutionStatus(e.Status) || e.Coverage.Status != e.Status || e.Coverage.ToolID != e.ToolID || e.Coverage.Capability == "" || e.Coverage.Reason == "" {
		return errors.New("execution requires a matching explicit coverage status and reason")
	}
	if e.Status == Succeeded || e.Status == NoFindings || e.Status == Partial {
		if err := e.Sandbox.Validate(); err != nil {
			return fmt.Errorf("execution sandbox: %w", err)
		}
		if len(e.RawArtifacts) == 0 {
			return errors.New("executed adapter outcome requires protected raw artifact")
		}
	}
	if e.InputArtifact != nil {
		if !validRawArtifact(*e.InputArtifact, "") {
			return errors.New("input artifact lineage is invalid")
		}
	}
	for _, raw := range e.RawArtifacts {
		if !validRawArtifact(raw, e.ID) {
			return errors.New("raw artifact lineage is invalid")
		}
	}
	return nil
}

func validRawArtifact(raw artifact.RawArtifact, executionID string) bool {
	return (executionID == "" || raw.ExecutionID == executionID) && raw.ExecutionID != "" &&
		sha256Reference.MatchString(raw.SHA256) && raw.Path == "raw/sha256/"+raw.SHA256[7:] &&
		raw.Size >= 0
}

func validExecutionStatus(status string) bool {
	switch status {
	case Succeeded, NoFindings, Partial, Unavailable, Unsupported, TimedOut, Failed, PolicyBlocked:
		return true
	default:
		return false
	}
}
