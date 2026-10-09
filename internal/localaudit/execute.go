package localaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

const (
	baseRuntime     = "sha256:8ec5c4cb7273dc9cb3a17ea920623700f7fdeabc9dcb52620b569f0f7434f97f"
	scancodeRuntime = "sha256:a8117f2f750833cc081c81d19bbf6c7063970ce47ae61147fbbd478682c18fba"
)

type auditPaths struct {
	targetRoot    string
	evidenceRoot  string
	toolchainRoot string
	rulePackRoot  string
	auditID       string
	output        io.Writer
}

// executeAudit is called only after the workflow has validated confirmation and
// exclusively reserved its output directories. The executor is injectable for offline tests.
func executeAudit(ctx context.Context, paths auditPaths, prepared preparedAudit, executor scannerExecutor) (runner.Record, error) {
	producer, err := buildinfo.Current()
	if err != nil {
		return runner.Record{}, fmt.Errorf("PAO producer identity: %w", err)
	}
	before, manifests, lock := prepared.snapshot, prepared.manifests, prepared.plan
	lockBytes, err := plan.LockJSON(lock)
	if err != nil {
		return runner.Record{}, err
	}
	if err := writeOnce(filepath.Join(paths.evidenceRoot, "plan.lock.json"), lockBytes, 0o600); err != nil {
		return runner.Record{}, err
	}
	captured, err := target.CaptureContext(ctx, paths.targetRoot, filepath.Join(paths.evidenceRoot, "input"), before)
	if err != nil {
		return runner.Record{}, fmt.Errorf("protected target capture: %w", err)
	}
	paths.targetRoot = filepath.FromSlash(captured.Root)
	store, err := artifact.Open(paths.evidenceRoot)
	if err != nil {
		return runner.Record{}, err
	}
	registry := prepared.registry
	if registry == nil {
		return runner.Record{}, errors.New("verified toolchain registry is unavailable")
	}
	manifestByID := make(map[string]adapter.Manifest, len(manifests))
	nodeByID := make(map[string]plan.AdapterNode, len(lock.Nodes))
	for _, manifest := range manifests {
		manifestByID[manifest.ID] = manifest
	}
	for _, node := range lock.Nodes {
		nodeByID[node.ID] = node
	}
	selectedIDs := make(map[string]bool, len(prepared.ids))
	for _, id := range prepared.ids {
		selectedIDs[id] = true
	}
	selected := func(id string) bool { return selectedIDs[id] }
	baseHost := prepared.baseHost
	scancodeHost := prepared.scancodeHost
	strong := runner.SandboxProperties{Isolation: runner.StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}
	tool := func(parts ...string) string { return filepath.Join(append([]string{paths.toolchainRoot}, parts...)...) }
	work := func(id string) string { return filepath.Join(paths.evidenceRoot, "work", id) }
	executions := make([]runner.ToolExecution, 0, 10)
	execute := func(spec runner.ExecutionSpec, host runner.DockerHost) (outcome runner.ToolExecution) {
		progress := startProgress(paths.output, spec.AdapterID, len(executions)+1, len(prepared.ids), 10*time.Second)
		defer func() { progress.finish(outcome) }()
		node := nodeByID[spec.AdapterID]
		if node.Status == "SKIPPED_NOT_APPLICABLE" {
			outcome := blocked(paths.auditID, lock, manifestByID[spec.AdapterID], node, spec.AdapterID, "SKIPPED_NOT_APPLICABLE: no matching inputs")
			outcome.Status, outcome.Coverage.Status, outcome.Coverage.ReasonCode = runner.Unsupported, runner.Unsupported, toolchain.ReasonNotApplicable
			return outcome
		}
		if node.Status == "UNSUPPORTED" {
			outcome := unsupported(paths.auditID, lock, manifestByID[spec.AdapterID], node, spec.AdapterID, "detected input is outside the approved adapter coverage")
			if len(node.SupportReasons) > 0 {
				outcome.Coverage.ReasonCode = node.SupportReasons[0]
			}
			return outcome
		}
		if prepared.catalogTools != nil {
			var err error
			id := spec.AdapterID
			spec, host, err = prepared.catalogSpec(spec, manifestByID[id])
			if err != nil {
				return blocked(paths.auditID, lock, manifestByID[id], nodeByID[id], id, "catalog execution declaration rejected")
			}
		}
		if err := os.MkdirAll(spec.TemporaryDir, 0o700); err != nil {
			return blocked(paths.auditID, lock, manifestByID[spec.AdapterID], node, spec.AdapterID, "temporary output unavailable")
		}
		var runErr error
		outcome, runErr = executor(ctx, runner.HostRunner{Registry: registry, Host: host, Artifacts: store, Progress: progress.stage}, spec, manifestByID[spec.AdapterID], lock.PlanDigest, node.ConfigDigest, paths.auditID+"-"+spec.AdapterID, node.Capability)
		if outcome.ID == "" {
			outcome = blocked(paths.auditID, lock, manifestByID[spec.AdapterID], node, spec.AdapterID, "adapter rejected before execution")
		}
		if runErr != nil && (outcome.Status == runner.Succeeded || outcome.Status == runner.NoFindings) {
			outcome.Status, outcome.Coverage.Status = runner.Failed, runner.Failed
			outcome.DiagnosticCode = "INVALID_LAUNCH_RESULT"
			outcome.Coverage.Reason = "executor returned an error with a successful status"
		}
		return outcome
	}
	makeSpec := func(id, toolPath, toolDigest, runtimeDigest, outputFile, mediaType string, args []string, env map[string]string, timeout int) runner.ExecutionSpec {
		temporary := work(id)
		return runner.ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: id, ToolID: id, ToolPath: toolPath, ToolDigest: "sha256:" + toolDigest, RuntimeDigest: runtimeDigest, OutputFile: outputFile, OutputMediaType: mediaType, Arguments: args, TargetRoot: paths.targetRoot, TemporaryDir: temporary, Environment: env, TimeoutSeconds: timeout, MemoryMB: 1024, ContainerName: "pao-" + paths.auditID + "-" + id, Sandbox: strong}
	}

	syftTemp := work("syft")
	syftOutput := filepath.Join(syftTemp, "syft.json")
	syftCycloneDX := filepath.Join(syftTemp, "syft.cdx.json")
	syft := makeSpec("syft", tool("syft", "1.51.1", "bin", "syft"), "abca2def61de9952fa06d3977bb1e064818facb9badfce502b450d3d6846a91f", baseRuntime, "syft.json", "application/vnd.syft+json", []string{"scan", "dir:" + paths.targetRoot, "--output", "json=" + syftOutput, "--output", "cyclonedx-json=" + syftCycloneDX}, map[string]string{}, 900)
	syft.AdditionalOutputs = []runner.DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}}
	var syftExecution runner.ToolExecution
	if selected("syft") {
		syftExecution = execute(syft, baseHost)
		executions = append(executions, syftExecution)
	}
	if selected("sbomqs") {
		input, ok := capturedCycloneDX(syftExecution)
		if prepared.sbomqs == nil {
			reason := "sbomqs has no owner-approved local executable, version and SHA-256"
			if prepared.sbomqsError != nil {
				reason = "sbomqs owner approval record is missing, malformed or stale"
			}
			if !ok {
				reason += "; Syft did not produce CycloneDX evidence"
				executions = append(executions, unavailable(paths.auditID, lock, manifestByID["sbomqs"], nodeByID["sbomqs"], "sbomqs", reason, nil))
			} else {
				executions = append(executions, unavailable(paths.auditID, lock, manifestByID["sbomqs"], nodeByID["sbomqs"], "sbomqs", reason, &input))
			}
			fmt.Fprintln(paths.output, "sbomqs: перевірку якості не запущено — локальний інструмент ще не схвалено за конкретною версією та SHA-256.")
		} else if !ok {
			executions = append(executions, unsupported(paths.auditID, lock, manifestByID["sbomqs"], nodeByID["sbomqs"], "sbomqs", "Syft did not produce CycloneDX evidence"))
			fmt.Fprintln(paths.output, "sbomqs: перевірку якості не запущено — Syft не створив придатний CycloneDX SBOM.")
		} else {
			inputPath := filepath.Join(paths.evidenceRoot, filepath.FromSlash(input.Path))
			candidate := prepared.sbomqs
			sbomqsSpec := makeSpec("sbomqs", tool("sbomqs", filepath.FromSlash(candidate.Binary)), candidate.Record.SHA256, baseRuntime, "", "", []string{"score", inputPath, "--legacy", "--json"}, map[string]string{}, 300)
			sbomqsSpec.InputPath = inputPath
			sbomqsSpec.InputDigest = input.SHA256
			outcome := execute(sbomqsSpec, baseHost)
			outcome.InputArtifact = &input
			executions = append(executions, outcome)
		}
	}

	if selected("grype") && usableSyftSBOM(syftExecution) {
		inputPath := filepath.Join(paths.evidenceRoot, filepath.FromSlash(findArtifact(syftExecution.RawArtifacts, "application/vnd.syft+json").Path))
		grypeTemp := work("grype")
		grypeOutput := filepath.Join(grypeTemp, "grype.json")
		grype := makeSpec("grype", tool("grype", "0.118.0", "bin", "grype"), "91705979c6ccb736b87e3250831f5e1a35f13767fd2032ffa85c55b1e6f58f90", baseRuntime, "grype.json", "application/json", []string{"sbom:" + inputPath, "--output", "json", "--file", grypeOutput}, map[string]string{"GRYPE_DB_CACHE_DIR": "/pao/database", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}, 900)
		grype.InputPath = inputPath
		grype.InputDigest = findArtifact(syftExecution.RawArtifacts, "application/vnd.syft+json").SHA256
		grype.DatabasePath = tool("grype", "0.118.0", "database", "2026-09-01-prep")
		grype.DatabaseDigest = "sha256:7feb9b9d695846dee52b82d78c1124f54355f88dc3edcdad4838be3acf22eb4d"
		executions = append(executions, execute(grype, baseHost))
	} else if selected("grype") {
		executions = append(executions, blocked(paths.auditID, lock, manifestByID["grype"], nodeByID["grype"], "grype", "Syft did not produce a usable successful SBOM"))
		fmt.Fprintln(paths.output, "Grype: перевірку не запущено — немає придатного результату Syft. Це не відсутність вразливостей.")
	}

	osvTemp := work("osv-scanner")
	osvOutput := filepath.Join(osvTemp, "osv-scanner.json")
	osv := makeSpec("osv-scanner", tool("osv-scanner", "2.5.1", "bin", "osv-scanner_linux_amd64"), "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be", baseRuntime, "osv-scanner.json", "application/json", []string{"scan", "source", paths.targetRoot, "--recursive", "--offline", "--offline-vulnerabilities", "--format=json", "--output-file", osvOutput}, map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/pao/database"}, 900)
	// The readable copy has identical metadata/data hashes and the original review age.
	osv.DatabasePath = tool("osv-scanner", "2.5.1", "database", "2026-09-03-readable-v1")
	osv.DatabaseDigest = "sha256:7972609e63c4e6b3d1c5bfc61bff788e6161999bf4eea7b34dfde76171894d17"
	if selected("osv-scanner") {
		executions = append(executions, execute(osv, baseHost))
	}

	scancodeTemp := work("scancode")
	scancodeOutput := filepath.Join(scancodeTemp, "scancode.json")
	// Docker limits this adapter to one CPU; pin one worker and a bounded per-file
	// timeout instead of inheriting the host's much larger CPU count.
	scancode := makeSpec("scancode", tool("scancode", "32.5.0", "bin", "scancode-toolkit-v32.5.0", "scancode"), "50add1b40ec7bd25592c663386d98fbef280d3f668f5ab9f89965ed0bf7583dc", scancodeRuntime, "scancode.json", "application/json", []string{"--license", "--copyright", "--package", "--processes", "1", "--timeout", "300", "--json", scancodeOutput, paths.targetRoot}, map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"}, 1800)
	scancode.StatePath = tool("scancode", "32.5.0", "state", "2026-09-01-synthetic-v1")
	scancode.StateDigest = "sha256:962f62028d63d508d84550060664b5dd76dd53cc1bb5a3a6cd25ee9abf510d45"
	scancode.StateEntrypoint = "scancode-toolkit-v32.5.0/venv/bin/scancode"
	scancode.LicenseDataDigest = "sha256:62504b97820541494cd7d364be0bb70f1d1da4c9d9c45323923272c0e0b73099"
	scancode.MemoryMB = 4096
	if selected("scancode") {
		executions = append(executions, execute(scancode, scancodeHost))
	}

	reuse := makeSpec("reuse", tool("reuse", "6.2.0", "bin", "reuse-6.2.0.tar.gz"), "4feae057a2334c9a513e6933cdb9be819d8b822f3b5b435a36138bd218897d23", scancodeRuntime, "", "", []string{"-m", "reuse", "--root", paths.targetRoot, "lint", "--json"}, map[string]string{}, 1800)
	reuse.StatePath = tool("reuse", "6.2.0", "state", "2026-09-01-linux-v1")
	reuse.StateDigest = "sha256:6a69f199873ad41e9e416b6be707c8fe44e331108adf8860916ba9aa7b3d8da7"
	reuse.StateEntrypoint = "venv/bin/python"
	if selected("reuse") {
		executions = append(executions, execute(reuse, scancodeHost))
	}

	trivyTemp := work("trivy")
	trivyOutput := filepath.Join(trivyTemp, "trivy.json")
	trivy := makeSpec("trivy", tool("trivy", "0.74.0", "bin", "trivy"), "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791", baseRuntime, "trivy.json", "application/json", []string{"filesystem", "--scanners", "vuln", "--timeout", "15m", "--cache-dir", tool("trivy", "0.74.0", "database", "2026-09-01-prep"), "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--format", "json", "--output", trivyOutput, paths.targetRoot}, map[string]string{}, 1800)
	trivy.MemoryMB = 2048
	trivy.DatabasePath = tool("trivy", "0.74.0", "database", "2026-09-01-prep")
	trivy.DatabaseDigest = "sha256:d459fb9fa38c6c6e43ea8504ce13852c683e6a7684e55f588cde67680fb84ceb"
	if selected("trivy") {
		executions = append(executions, execute(trivy, baseHost))
	}

	gitleaksTemp := work("gitleaks")
	gitleaksOutput := filepath.Join(gitleaksTemp, "gitleaks.json")
	gitleaks := makeSpec("gitleaks", tool("gitleaks", "8.30.1", "bin", "gitleaks"), "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509", baseRuntime, "gitleaks.json", "application/json", []string{"dir", paths.targetRoot, "--redact=100", "--exit-code=10", "--report-format=json", "--report-path", gitleaksOutput}, map[string]string{}, 900)
	if selected("gitleaks") {
		executions = append(executions, execute(gitleaks, baseHost))
	}

	opengrepTemp := work("opengrep")
	opengrepOutput := filepath.Join(opengrepTemp, "opengrep.json")
	opengrep := makeSpec("opengrep", tool("opengrep", "1.29.0", "bin", "opengrep_manylinux_x86"), "3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13", baseRuntime, "opengrep.json", "application/json", []string{"scan", "--config", paths.rulePackRoot, "--json", "--json-output", opengrepOutput, paths.targetRoot}, map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}, 1200)
	opengrep.StatePath = tool("opengrep", "1.29.0", "state", "2026-09-01-synthetic-v1")
	opengrep.StateDigest = "sha256:11f61aee03f7710aa7488ff11174d9dac77c8cf4fd2962e98a2d4703ba38b424"
	opengrep.RulePackPath = paths.rulePackRoot
	opengrep.RulePackDigest = "sha256:891a4523a886ce903e4488b6e5d49d00f1f28d1efedb0822f8d52f4f88773deb"
	if selected("opengrep") {
		executions = append(executions, execute(opengrep, baseHost))
	}

	zizmor := makeSpec("zizmor", tool("zizmor", "1.29.0", "bin", "zizmor"), "a3331b0a69fc0d8bf8087b0d74d5424602c5a0f2fc2770afe2e908a1295692b5", baseRuntime, "", "", []string{"--offline", "--format=json-v1", paths.targetRoot}, map[string]string{}, 900)
	if selected("zizmor") {
		executions = append(executions, execute(zizmor, baseHost))
	}

	fmt.Fprintln(paths.output, "Звіряємо незмінність файлів проєкту та зберігаємо запис запуску.")
	after, snapshotErr := target.SnapshotRootContext(ctx, paths.targetRoot)
	record := runner.Record{Producer: &producer, Version: runner.RunRecordVersion, PlanDigest: lock.PlanDigest, TargetBefore: before, TargetAfter: after, Executions: executions}
	recordBytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return runner.Record{}, err
	}
	if err := writeOnce(filepath.Join(paths.evidenceRoot, "run-record.json"), append(recordBytes, '\n'), 0o600); err != nil {
		return record, err
	}
	if snapshotErr != nil {
		return record, snapshotErr
	}
	if err := record.Validate(); err != nil {
		return record, fmt.Errorf("run record validation: %w", err)
	}
	return record, nil
}

func usableSyftSBOM(execution runner.ToolExecution) bool {
	return execution.Status == runner.Succeeded &&
		findArtifact(execution.RawArtifacts, "application/vnd.syft+json") != nil
}

func capturedCycloneDX(execution runner.ToolExecution) (artifact.RawArtifact, bool) {
	if execution.Status != runner.Succeeded {
		return artifact.RawArtifact{}, false
	}
	ref := findArtifact(execution.RawArtifacts, "application/vnd.cyclonedx+json")
	if ref == nil {
		return artifact.RawArtifact{}, false
	}
	return *ref, true
}

func findArtifact(artifacts []artifact.RawArtifact, mediaType string) *artifact.RawArtifact {
	var found *artifact.RawArtifact
	for index := range artifacts {
		if artifacts[index].MediaType != mediaType {
			continue
		}
		if found != nil {
			return nil
		}
		found = &artifacts[index]
	}
	return found
}

func buildRegistry(toolchainRoot string) (*toolchain.Registry, *toolchain.OwnerApprovedTool, error) {
	approvedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	records := []toolchain.Record{
		{ID: "syft", Version: "1.51.1", SHA256: "abca2def61de9952fa06d3977bb1e064818facb9badfce502b450d3d6846a91f", SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
		{ID: "grype", Version: "0.118.0", SHA256: "91705979c6ccb736b87e3250831f5e1a35f13767fd2032ffa85c55b1e6f58f90", SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", DatabaseSHA256: "7feb9b9d695846dee52b82d78c1124f54355f88dc3edcdad4838be3acf22eb4d", DatabaseAt: approvedAt, DatabaseEnvironment: map[string]string{"GRYPE_DB_CACHE_DIR": "/pao/database", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}, RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
		{ID: "osv-scanner", Version: "2.5.1", SHA256: "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be", SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", DatabaseSHA256: "7972609e63c4e6b3d1c5bfc61bff788e6161999bf4eea7b34dfde76171894d17", DatabaseAt: approvedAt, DatabaseEnvironment: map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/pao/database"}, RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
		{ID: "scancode", Version: "32.5.0", SHA256: "50add1b40ec7bd25592c663386d98fbef280d3f668f5ab9f89965ed0bf7583dc", SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", StateSHA256: "962f62028d63d508d84550060664b5dd76dd53cc1bb5a3a6cd25ee9abf510d45", StateAt: approvedAt, StateEnvironment: map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"}, RuntimeSHA256: scancodeRuntime[7:], RuntimeAt: approvedAt, LicenseDataSHA256: "62504b97820541494cd7d364be0bb70f1d1da4c9d9c45323923272c0e0b73099", LicenseDataAt: approvedAt},
		{ID: "reuse", Version: "6.2.0", SHA256: "4feae057a2334c9a513e6933cdb9be819d8b822f3b5b435a36138bd218897d23", SourceLicense: "GPL-3.0-or-later", Redistribution: "user-installed-only", StateSHA256: "6a69f199873ad41e9e416b6be707c8fe44e331108adf8860916ba9aa7b3d8da7", StateAt: approvedAt, RuntimeSHA256: scancodeRuntime[7:], RuntimeAt: approvedAt},
		{ID: "trivy", Version: "0.74.0", SHA256: "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791", SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", DatabaseSHA256: "d459fb9fa38c6c6e43ea8504ce13852c683e6a7684e55f588cde67680fb84ceb", DatabaseAt: approvedAt, RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
		{ID: "gitleaks", Version: "8.30.1", SHA256: "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509", SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
		{ID: "opengrep", Version: "1.29.0", SHA256: "3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13", SourceLicense: "LGPL-2.1-only", Redistribution: "user-installed-only", StateSHA256: "11f61aee03f7710aa7488ff11174d9dac77c8cf4fd2962e98a2d4703ba38b424", StateAt: approvedAt, StateEnvironment: map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}, RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt, RulePackSHA256: "891a4523a886ce903e4488b6e5d49d00f1f28d1efedb0822f8d52f4f88773deb", RulePackAt: approvedAt},
		{ID: "zizmor", Version: "1.29.0", SHA256: "a3331b0a69fc0d8bf8087b0d74d5424602c5a0f2fc2770afe2e908a1295692b5", SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: baseRuntime[7:], RuntimeAt: approvedAt},
	}
	metadata := filepath.Join(toolchainRoot, "sbomqs", "approved-tool.json")
	ownerTool, err := toolchain.LoadOwnerApprovedTool(metadata, "sbomqs", time.Now().UTC())
	if err == nil {
		ownerTool.Record.RuntimeSHA256, ownerTool.Record.RuntimeAt = baseRuntime[7:], ownerTool.ApprovedAt
		records = append(records, ownerTool.Record)
	} else if !errors.Is(err, os.ErrNotExist) {
		registry, registryErr := toolchain.New(records)
		return registry, nil, errOr(registryErr, err)
	}
	registry, registryErr := toolchain.New(records)
	if registryErr != nil {
		return nil, nil, registryErr
	}
	if err != nil {
		return registry, nil, nil
	}
	return registry, &ownerTool, nil
}

func errOr(first, second error) error {
	if first != nil {
		return first
	}
	return second
}

func loadManifests(manifestRoot string) ([]adapter.Manifest, error) {
	entries, err := os.ReadDir(manifestRoot)
	if err != nil {
		return nil, err
	}
	manifests := make([]adapter.Manifest, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(manifestRoot, entry.Name(), "manifest.json")
		if err := auditconfig.CheckPath(path, false); err != nil {
			return nil, err
		}
		manifest, err := adapter.LoadFile(path)
		if err != nil {
			return nil, err
		}
		if manifest.ID != entry.Name() {
			return nil, errors.New("adapter ID must match its directory")
		}
		manifests = append(manifests, manifest)
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].ID < manifests[j].ID })
	if len(manifests) != 10 {
		return nil, fmt.Errorf("expected 10 adapter manifests, got %d", len(manifests))
	}
	return manifests, nil
}

func blocked(auditID string, lock plan.Plan, manifest adapter.Manifest, node plan.AdapterNode, id, reason string) runner.ToolExecution {
	digest, _ := adapter.Digest(manifest)
	return runner.ToolExecution{ID: auditID + "-" + id, PlanDigest: lock.PlanDigest, ManifestDigest: digest, AdapterID: id, ToolID: id, ConfigDigest: node.ConfigDigest, Status: runner.PolicyBlocked, Coverage: toolchain.Coverage{ToolID: id, Capability: node.Capability, Status: runner.PolicyBlocked, Reason: reason}}
}

func unavailable(auditID string, lock plan.Plan, manifest adapter.Manifest, node plan.AdapterNode, id, reason string, input *artifact.RawArtifact) runner.ToolExecution {
	digest, _ := adapter.Digest(manifest)
	coverage, err := toolchain.ExplicitGap(id, node.Capability, toolchain.ReasonToolUnverified, reason)
	if err != nil {
		coverage = toolchain.Coverage{ToolID: id, Capability: node.Capability, Status: runner.Unavailable, Reason: "verified local tool is unavailable"}
	}
	return runner.ToolExecution{ID: auditID + "-" + id, PlanDigest: lock.PlanDigest, ManifestDigest: digest, AdapterID: id, ToolID: id, ConfigDigest: node.ConfigDigest, Status: runner.Unavailable, Coverage: coverage, InputArtifact: input}
}

func unsupported(auditID string, lock plan.Plan, manifest adapter.Manifest, node plan.AdapterNode, id, reason string) runner.ToolExecution {
	digest, _ := adapter.Digest(manifest)
	return runner.ToolExecution{ID: auditID + "-" + id, PlanDigest: lock.PlanDigest, ManifestDigest: digest, AdapterID: id, ToolID: id, ConfigDigest: node.ConfigDigest, Status: runner.Unsupported, Coverage: toolchain.Coverage{ToolID: id, Capability: node.Capability, Status: runner.Unsupported, Reason: reason}}
}

func writeOnce(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite immutable audit artifact: %s", path)
		}
		return err
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}
