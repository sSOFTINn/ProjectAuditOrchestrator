package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

// IsolationHost is implemented by a host-owned container/VM integration. PAO
// never passes a shell string, inherited environment or target write authority
// to it; an implementation must independently enforce the declared properties.
type IsolationHost interface {
	Capabilities(context.Context) (SandboxProperties, error)
	Launch(context.Context, ExecutionSpec) (LaunchResult, error)
}

type runtimeIdentityHost interface {
	RuntimeIdentity() string
}

// prepareExecutionHost fixes native host executables before any capability
// command or scanner launch consumes them. Its cleanup follows host teardown.
type prepareExecutionHost interface {
	prepareExecution(context.Context, ExecutionSpec) (IsolationHost, func() error, error)
}

type LaunchResult struct {
	Status          string
	Reason          string
	MediaType       string
	RawOutput       []byte
	Stderr          []byte
	StderrTruncated bool
	StdoutTruncated bool
	ExitCode        *int
	DiagnosticCode  string
}

// CapabilityError proves that a scanner was not launched because a mandatory
// control or prerequisite was unavailable. It must be recorded as POLICY_BLOCKED, never pass.
type CapabilityError struct{ Reason, ReasonCode string }

func (e *CapabilityError) Error() string { return "container-vm capability unavailable: " + e.Reason }

type HostRunner struct {
	Registry  *toolchain.Registry
	Host      IsolationHost
	Artifacts *artifact.Store
	Progress  func(Stage)
	Now       func() time.Time
}

// ExecuteDeclared binds a launch request to a validated immutable adapter contract.
func (h HostRunner) ExecuteDeclared(ctx context.Context, spec ExecutionSpec, manifest adapter.Manifest, planDigest, configDigest, executionID, capability string) (ToolExecution, error) {
	if err := manifest.Validate(); err != nil {
		return ToolExecution{}, err
	}
	manifestDigest, err := adapter.Digest(manifest)
	if err != nil {
		return ToolExecution{}, err
	}
	blocked := func(reason string) (ToolExecution, error) {
		return ToolExecution{ID: executionID, PlanDigest: planDigest, ManifestDigest: manifestDigest, AdapterID: spec.AdapterID, ToolID: spec.ToolID, ToolDigest: spec.ToolDigest, ConfigDigest: configDigest, DatabaseDigest: spec.DatabaseDigest, StateDigest: spec.StateDigest, RuntimeDigest: spec.RuntimeDigest, RulePackDigest: spec.RulePackDigest, LicenseDataDigest: spec.LicenseDataDigest, Status: PolicyBlocked, DiagnosticCode: "DECLARATION_REJECTED", Coverage: toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: PolicyBlocked, ReasonCode: toolchain.ReasonToolUnverified, Reason: reason}}, &CapabilityError{Reason: reason}
	}
	if spec.TimeoutSeconds > manifest.TimeoutSeconds {
		return blocked("execution timeout exceeds the validated adapter limit")
	}
	if spec.MaxOutputBytes == 0 {
		spec.MaxOutputBytes = min(manifest.MaxOutputBytes, maxDeclaredOutputBytes)
	} else if spec.MaxOutputBytes > manifest.MaxOutputBytes {
		return blocked("execution output limit exceeds the validated adapter limit")
	}
	if manifest.ID != spec.AdapterID || manifest.ID != spec.ToolID {
		outcome := ToolExecution{ID: executionID, PlanDigest: planDigest, ManifestDigest: manifestDigest, AdapterID: spec.AdapterID, ToolID: spec.ToolID, ConfigDigest: configDigest, Status: PolicyBlocked, Coverage: toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: PolicyBlocked, ReasonCode: toolchain.ReasonToolUnverified, Reason: "execution spec does not match validated adapter manifest"}}
		return outcome, &CapabilityError{Reason: "execution spec does not match validated adapter manifest"}
	}
	expectedArguments, err := expandManifestArguments(manifest.FixedArguments, spec)
	if err != nil || !equalArguments(expectedArguments, spec.Arguments) {
		outcome := ToolExecution{ID: executionID, PlanDigest: planDigest, ManifestDigest: manifestDigest, AdapterID: spec.AdapterID, ToolID: spec.ToolID, ToolDigest: spec.ToolDigest, ConfigDigest: configDigest, DatabaseDigest: spec.DatabaseDigest, StateDigest: spec.StateDigest, RuntimeDigest: spec.RuntimeDigest, RulePackDigest: spec.RulePackDigest, LicenseDataDigest: spec.LicenseDataDigest, Status: PolicyBlocked, Coverage: toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: PolicyBlocked, Reason: "execution arguments do not match validated adapter manifest"}}
		return outcome, &CapabilityError{Reason: "execution arguments do not match validated adapter manifest"}
	}
	if err := manifest.AllowsEnvironment(spec.Environment); err != nil {
		outcome := ToolExecution{ID: executionID, PlanDigest: planDigest, ManifestDigest: manifestDigest, AdapterID: spec.AdapterID, ToolID: spec.ToolID, ConfigDigest: configDigest, StateDigest: spec.StateDigest, Status: PolicyBlocked, Coverage: toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: PolicyBlocked, Reason: "execution environment does not match validated adapter manifest"}}
		return outcome, &CapabilityError{Reason: "execution environment does not match validated adapter manifest"}
	}
	version, err := h.Registry.VersionForDigest(spec.ToolID, spec.ToolDigest)
	if err != nil || manifest.AllowsToolVersion(version) != nil {
		return blocked("approved tool version is not compatible with the validated adapter parser")
	}
	spec.successExitCodes = append([]int(nil), manifest.SuccessExitCodes...)
	outcome, runErr := h.Execute(ctx, spec, planDigest, configDigest, executionID, capability)
	outcome.ManifestDigest = manifestDigest
	return outcome, runErr
}

func expandManifestArguments(arguments []string, spec ExecutionSpec) ([]string, error) {
	expanded := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		replacements := map[string]string{
			"${target}":   spec.TargetRoot,
			"${input}":    spec.InputPath,
			"${database}": spec.DatabasePath,
			"${rulepack}": spec.RulePackPath,
		}
		if spec.OutputFile != "" {
			replacements["${output}"] = filepath.Join(spec.TemporaryDir, filepath.FromSlash(spec.OutputFile))
		}
		for index, output := range spec.AdditionalOutputs {
			replacements[fmt.Sprintf("${additional_output_%d}", index)] = filepath.Join(spec.TemporaryDir, filepath.FromSlash(output.File))
		}
		value := argument
		for placeholder, replacement := range replacements {
			if strings.Contains(value, placeholder) {
				if replacement == "" {
					return nil, fmt.Errorf("manifest requires declared %s", strings.Trim(placeholder, "${}"))
				}
				value = strings.ReplaceAll(value, placeholder, replacement)
			}
		}
		if strings.Contains(value, "${") {
			return nil, errors.New("manifest contains an unsupported argument placeholder")
		}
		expanded = append(expanded, value)
	}
	return expanded, nil
}

// ManifestArguments expands a manifest's fixed argument templates for a spec.
// It grants no execution authority; ExecuteDeclared still validates the manifest
// and the resulting invocation before the host can launch it.
func ManifestArguments(manifest adapter.Manifest, spec ExecutionSpec) ([]string, error) {
	return expandManifestArguments(manifest.FixedArguments, spec)
}

func equalArguments(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Execute verifies the installed tool before requesting host isolation. It fails
// closed when the host is absent or cannot prove every required control.
func (h HostRunner) Execute(ctx context.Context, spec ExecutionSpec, planDigest, configDigest, executionID, capability string) (execution ToolExecution, executionErr error) {
	currentStage := StageValidate
	stage := func(s Stage) {
		currentStage = s
		if h.Progress != nil {
			h.Progress(s)
		}
	}
	stage(StageValidate)
	lineage := func() ToolExecution {
		return ToolExecution{
			ID: executionID, PlanDigest: planDigest, AdapterID: spec.AdapterID, ToolID: spec.ToolID,
			ToolDigest: spec.ToolDigest, ConfigDigest: configDigest, DatabaseDigest: spec.DatabaseDigest, StateDigest: spec.StateDigest, RuntimeDigest: spec.RuntimeDigest,
			RulePackDigest: spec.RulePackDigest, LicenseDataDigest: spec.LicenseDataDigest,
		}
	}
	blocked := func(reason string) (ToolExecution, error) {
		outcome := lineage()
		outcome.Status = PolicyBlocked
		outcome.DiagnosticCode = stageFailureCode(currentStage)
		outcome.Coverage = toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: PolicyBlocked, Reason: reason}
		return outcome, &CapabilityError{Reason: reason}
	}
	if err := spec.Validate(); err != nil {
		return blocked(err.Error())
	}
	if h.Registry == nil || h.Host == nil || h.Artifacts == nil {
		return blocked("verified toolchain, protected artifact store or container-vm host is unavailable")
	}
	stage(StageApproval)
	if spec.ToolDigest != "" {
		if err := h.Registry.VerifyToolDigest(spec.ToolID, spec.ToolDigest); err != nil {
			return blocked("approved tool digest is unavailable: " + err.Error())
		}
	}
	if spec.DatabaseDigest != "" {
		if err := h.Registry.VerifyDatabase(spec.ToolID, spec.DatabaseDigest, spec.Environment); err != nil {
			return blocked("approved database configuration is unavailable: " + err.Error())
		}
	}
	if spec.StateDigest != "" {
		if err := h.Registry.VerifyPreparedState(spec.ToolID, spec.StateDigest, spec.Environment); err != nil {
			return blocked("approved prepared-state configuration is unavailable: " + err.Error())
		}
	}
	if spec.RuntimeDigest != "" {
		if err := h.Registry.VerifyRuntimeDigest(spec.ToolID, spec.RuntimeDigest); err != nil {
			return blocked("approved runtime configuration is unavailable: " + err.Error())
		}
		runtimeHost, ok := h.Host.(runtimeIdentityHost)
		if !ok || runtimeHost.RuntimeIdentity() != spec.RuntimeDigest {
			return blocked("container-vm host runtime identity does not match approved execution")
		}
	}
	if spec.RulePackDigest != "" {
		if err := h.Registry.VerifyRulePackDigest(spec.ToolID, spec.RulePackDigest); err != nil {
			return blocked("approved rule-pack configuration is unavailable: " + err.Error())
		}
	}
	if spec.LicenseDataDigest != "" {
		if err := h.Registry.VerifyLicenseDataDigest(spec.ToolID, spec.LicenseDataDigest); err != nil {
			return blocked("approved license-data configuration is unavailable: " + err.Error())
		}
	}
	// Approval freshness is checked here, after identity verification and before
	// calling the isolation host. Preview/preflight results are not launch authority.
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	if coverage := h.Registry.Preflight(executionRequirement(spec, capability), now().UTC()); coverage.Status != "AVAILABLE_NOT_STARTED" {
		outcome, err := blocked(coverage.Reason)
		outcome.Coverage.ReasonCode = coverage.ReasonCode
		return outcome, err
	}
	stage(StageTool)
	frozen, cleanupInputs, err := FreezeInputs(ctx, spec)
	if err != nil {
		return blocked("frozen approved inputs are unavailable: " + err.Error())
	}
	defer func() {
		if retainCleanupIfUnconfirmed(executionErr, cleanupInputs) {
			return
		}
		if err := cleanupInputs(); err != nil {
			execution.Status, execution.Coverage.Status, execution.DiagnosticCode = Failed, Failed, "INPUT_CLEANUP_FAILED"
			execution.Coverage.Reason = "private input cleanup failed"
			executionErr = errors.Join(executionErr, err)
		}
	}()
	spec = frozen
	spec.verifiedInputs = true
	if preparer, ok := h.Host.(prepareExecutionHost); ok {
		host, cleanupHost, err := preparer.prepareExecution(ctx, spec)
		if err != nil {
			return blocked("frozen host executables are unavailable: " + err.Error())
		}
		h.Host = host
		defer func() {
			if retainCleanupIfUnconfirmed(executionErr, cleanupHost) {
				return
			}
			if err := cleanupHost(); err != nil {
				execution.Status, execution.Coverage.Status, execution.DiagnosticCode = Failed, Failed, "INPUT_CLEANUP_FAILED"
				execution.Coverage.Reason = "private host executable cleanup failed"
				executionErr = errors.Join(executionErr, err)
			}
		}()
	}
	stage(StageIsolation)
	capabilities, err := h.Host.Capabilities(ctx)
	if err != nil {
		return blocked("container-vm capability probe failed: " + err.Error())
	}
	if err := capabilities.Validate(); err != nil {
		return blocked(err.Error())
	}
	stage(StageApproval)
	// Copying large prerequisites and probing a host can cross a freshness or
	// expiry boundary. Admission is not authority for a later launch.
	if coverage := h.Registry.Preflight(executionRequirement(spec, capability), now().UTC()); coverage.Status != "AVAILABLE_NOT_STARTED" {
		outcome, err := blocked(coverage.Reason)
		outcome.Coverage.ReasonCode = coverage.ReasonCode
		return outcome, err
	}
	spec.launchAdmission = func() error {
		coverage := h.Registry.Preflight(executionRequirement(spec, capability), now().UTC())
		if coverage.Status != "AVAILABLE_NOT_STARTED" {
			return &CapabilityError{Reason: coverage.Reason, ReasonCode: coverage.ReasonCode}
		}
		return nil
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutSeconds)*time.Second)
	defer cancel()
	stage(StageLaunch)
	result, err := h.Host.Launch(runCtx, spec)
	if err != nil {
		var admissionError *CapabilityError
		if errors.As(err, &admissionError) {
			stage(StageApproval)
			outcome, blockedErr := blocked(admissionError.Reason)
			outcome.Coverage.ReasonCode = admissionError.ReasonCode
			return outcome, blockedErr
		}
		var pending *UnconfirmedContainerCleanupError
		if errors.As(err, &pending) {
			executionErr = err
			result.Status, result.DiagnosticCode, result.Reason = Failed, "CONTAINER_CLEANUP_UNCONFIRMED", "container teardown could not be confirmed; operator recovery is required"
		} else {
			result.Status, result.DiagnosticCode, result.Reason = Failed, "HOST_START_FAILED", "container-vm host failed"
			if runCtx.Err() == context.DeadlineExceeded {
				result.Status, result.DiagnosticCode, result.Reason = TimedOut, "TIMED_OUT", "container-vm host timed out"
			} else if runCtx.Err() != nil {
				result.DiagnosticCode, result.Reason = "CANCELLED", "container-vm execution cancelled"
			}
		}
	}
	if !validExecutionStatus(result.Status) || result.Status == Unavailable || result.Status == Unsupported || result.Status == PolicyBlocked || (result.DiagnosticCode != "" && !KnownDiagnosticCode(result.DiagnosticCode)) {
		result.Status, result.DiagnosticCode, result.Reason = Failed, "INVALID_LAUNCH_RESULT", "host returned invalid launch status or diagnostic code"
	}
	if result.Reason == "" {
		result.Reason = "container-vm host completed"
	}
	if result.MediaType == "" {
		result.MediaType = dockerRawMediaType
		if result.DiagnosticCode == "" {
			result.Status, result.DiagnosticCode, result.Reason = Failed, "INVALID_LAUNCH_RESULT", "host did not identify raw output media type"
		}
	}
	if len(result.Stderr) > MaxDiagnosticBytes {
		result.Stderr = result.Stderr[:MaxDiagnosticBytes]
		result.StderrTruncated = true
	}
	if int64(len(result.RawOutput)) > outputBudget(spec) {
		result.RawOutput = result.RawOutput[:outputBudget(spec)]
		result.StdoutTruncated = true
	}
	if (result.StderrTruncated || result.StdoutTruncated) && (result.Status == Succeeded || result.Status == NoFindings) {
		result.Status, result.DiagnosticCode, result.Reason = Partial, "OUTPUT_LIMIT", "captured output truncated"
	}
	stage(StagePersist)
	outcome := lineage()
	outcome.Status = result.Status
	outcome.Sandbox = capabilities
	outcome.DiagnosticCode, outcome.ExitCode, outcome.StdoutTruncated = result.DiagnosticCode, result.ExitCode, result.StdoutTruncated
	outcome.Coverage = toolchain.Coverage{ToolID: spec.ToolID, Capability: capability, Status: result.Status, Reason: result.Reason}
	raw, rawErr := h.Artifacts.PutRaw(result.MediaType, result.RawOutput, executionID)
	if rawErr == nil {
		outcome.RawArtifacts = []artifact.RawArtifact{raw}
	}
	if rawErr == nil {
		remainingOutputBytes := outputBudget(spec) - int64(len(result.RawOutput))
		for _, declared := range spec.AdditionalOutputs {
			contents, err := readDeclaredOutput(spec.TemporaryDir, declared.File)
			if err != nil {
				rawErr = err
				break
			}
			if int64(len(contents)) > remainingOutputBytes {
				rawErr = errors.New("aggregate declared output limit exceeded")
				break
			}
			remainingOutputBytes -= int64(len(contents))
			additional, err := h.Artifacts.PutRaw(declared.MediaType, contents, executionID)
			if err != nil {
				rawErr = err
				break
			}
			outcome.RawArtifacts = append(outcome.RawArtifacts, additional)
		}
	}
	var diagnosticErr error
	if len(result.Stderr) > 0 || result.StderrTruncated {
		ref, storeErr := h.Artifacts.PutRaw(dockerRawMediaType, result.Stderr, executionID)
		diagnosticErr = storeErr
		if storeErr == nil {
			outcome.Diagnostics = []DiagnosticArtifact{{Stream: "stderr", Truncated: result.StderrTruncated, Artifact: ref}}
		}
	}
	if rawErr != nil || diagnosticErr != nil {
		outcome.Status, outcome.Coverage.Status = Failed, Failed
		outcome.DiagnosticCode = "EVIDENCE_STORE_FAILED"
		if diagnosticErr != nil {
			outcome.DiagnosticCode = "DIAGNOSTIC_STORAGE_FAILED"
		}
		outcome.Coverage.Reason = "protected evidence persistence failed"
		return outcome, errors.Join(executionErr, errors.New("protected evidence persistence failed"))
	}
	return outcome, executionErr
}

func executionRequirement(spec ExecutionSpec, capability string) toolchain.Requirement {
	return toolchain.Requirement{
		ToolID: spec.ToolID, Capability: capability,
		RequiresDatabase: spec.DatabaseDigest != "", MaximumDatabaseAge: toolchain.MaximumPrerequisiteAge,
		RequiresState: spec.StateDigest != "", MaximumStateAge: toolchain.MaximumPrerequisiteAge,
		RequiresRuntime: spec.RuntimeDigest != "", MaximumRuntimeAge: toolchain.MaximumPrerequisiteAge,
		RequiresRulePack: spec.RulePackDigest != "", MaximumRulePackAge: toolchain.MaximumPrerequisiteAge,
		RequiresLicenseData: spec.LicenseDataDigest != "", MaximumLicenseDataAge: toolchain.MaximumPrerequisiteAge,
	}
}
