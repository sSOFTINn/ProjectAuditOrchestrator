package runner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/sandbox"
)

const dockerRawMediaType = "application/octet-stream"
const maxDeclaredOutputBytes int64 = 64 << 20

// An explicit local pipe prevents the CLI's saved default context from routing
// paths or audit data to a remote daemon. Other backends need separate approval
// and acceptance evidence; a native Linux daemon is not a VM boundary.
const dockerDesktopLinuxEndpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"

// pidsLimit remains a hard ceiling. 128 is the smallest approved increase
// above the 65 threads Syft needed while cataloguing a full CPython runtime.
const pidsLimit = 128

var windowsAbsolutePath = regexp.MustCompile(`(?i)(^|[^a-z0-9_])[a-z]:[\\/]`)

// DockerHost launches a verified Linux tool only inside a content-addressed local
// Docker Desktop runtime. It requires Desktop's VM-backed Linux engine on
// Windows or Linux; it does not offer a native-process/kernel fallback.
type DockerHost struct {
	DockerPath        string
	DockerSHA256      string
	RuntimeImage      string // exact local image ID: sha256:<64 hex characters>
	RuntimeApproval   RuntimeApproval
	SandboxPath       string // PAO's bundled static Linux supervisor, never scanner code
	SandboxSHA256     string
	preparedNative    bool
	runDocker         dockerCommand
	runCaptured       capturedCommand
	now               func() time.Time
	connection        func() (dockerConnection, error)                                 // synthetic-test seam
	syntheticEnvelope func(ExecutionSpec, commandOutput, error) (commandOutput, error) // test-only protocol producer
}

func (h DockerHost) RuntimeIdentity() string { return h.RuntimeImage }

// RuntimeApproval binds a local immutable runtime to a human-owned, expiring
// review. A raw image digest without this record is not a clean runtime.
type RuntimeApproval struct {
	ID             string    `json:"id"`
	Owner          string    `json:"owner"`
	EvidenceDigest string    `json:"evidence_digest"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (a RuntimeApproval) Validate(now time.Time) error {
	if a.ID == "" || a.Owner == "" || !sha256Reference.MatchString(a.EvidenceDigest) || a.ExpiresAt.IsZero() {
		return errors.New("runtime approval requires ID, owner, SHA-256 evidence digest and expiry")
	}
	if !a.ExpiresAt.After(now) {
		return errors.New("runtime approval has expired")
	}
	return nil
}

type dockerCommand func(context.Context, string, ...string) ([]byte, error)

func (h DockerHost) Capabilities(ctx context.Context) (SandboxProperties, error) {
	if _, err := h.localConnection(); err != nil {
		return SandboxProperties{}, err
	}
	if err := validateImageID(h.RuntimeImage); err != nil {
		return SandboxProperties{}, err
	}
	if err := h.RuntimeApproval.Validate(h.currentTime()); err != nil {
		return SandboxProperties{}, err
	}
	output, err := h.command(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return SandboxProperties{}, fmt.Errorf("Docker server probe: %w", err)
	}
	if err := validateDesktopEngine(output); err != nil {
		return SandboxProperties{}, err
	}
	output, err = h.command(ctx, "image", "inspect", "--format", "{{.Id}}", h.RuntimeImage)
	if err != nil {
		return SandboxProperties{}, fmt.Errorf("runtime image probe: %w", err)
	}
	if strings.TrimSpace(string(output)) != h.RuntimeImage {
		return SandboxProperties{}, errors.New("runtime image identity does not match configured SHA-256")
	}
	output, err = h.command(ctx, "image", "inspect", "--format", "{{json .Config.Volumes}}", h.RuntimeImage)
	if err != nil {
		return SandboxProperties{}, fmt.Errorf("runtime volume probe: %w", err)
	}
	var imageVolumes map[string]json.RawMessage
	if err := json.Unmarshal(output, &imageVolumes); err != nil || len(imageVolumes) != 0 {
		return SandboxProperties{}, errors.New("runtime image declares unbounded writable volumes")
	}
	return SandboxProperties{
		Isolation:             StrongIsolation,
		RepositoryReadOnly:    true,
		TemporaryWriteOnly:    true,
		NetworkDenied:         true,
		EnvironmentSanitized:  true,
		ProcessTreeControlled: true,
		CPULimited:            true,
		MemoryLimited:         true,
		FilesystemIsolated:    true,
		CleanRuntime:          true,
	}, nil
}

func (h DockerHost) Launch(ctx context.Context, spec ExecutionSpec) (launched LaunchResult, launchErr error) {
	if err := spec.Validate(); err != nil {
		return LaunchResult{}, err
	}
	if h.runDocker == nil && h.runCaptured == nil && hasUnconfirmedTeardown() {
		return LaunchResult{}, errors.New("a prior container teardown is unconfirmed; operator recovery is required")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutSeconds)*time.Second)
	defer cancel()
	if spec.ContainerName == "" {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return LaunchResult{}, err
		}
		spec.ContainerName = "pao-" + hex.EncodeToString(nonce[:])
	}
	if err := validateImageID(h.RuntimeImage); err != nil {
		return LaunchResult{}, err
	}
	if spec.RuntimeDigest != "" && spec.RuntimeDigest != h.RuntimeImage {
		return LaunchResult{}, errors.New("execution runtime digest does not match Docker runtime image")
	}
	if err := h.RuntimeApproval.Validate(h.currentTime()); err != nil {
		return LaunchResult{}, err
	}
	cleanupAfter := func(cleanup func() error) {
		if retainCleanupIfUnconfirmed(launchErr, cleanup) {
			return
		}
		if err := cleanup(); err != nil {
			launched.Status, launched.DiagnosticCode, launched.Reason = Failed, "INPUT_CLEANUP_FAILED", "private input cleanup failed"
			launchErr = errors.Join(launchErr, err)
		}
	}
	if !h.preparedNative && h.runDocker == nil && h.runCaptured == nil {
		host, cleanup, err := h.prepareExecution(ctx, spec)
		if err != nil {
			return LaunchResult{}, err
		}
		h = host.(DockerHost)
		defer cleanupAfter(cleanup)
	}
	if !spec.verifiedInputs && h.runDocker == nil && h.runCaptured == nil {
		frozen, cleanup, err := FreezeInputs(ctx, spec)
		if err != nil {
			return LaunchResult{}, err
		}
		spec = frozen
		spec.verifiedInputs = true
		defer cleanupAfter(cleanup)
	}
	supervisor, err := h.supervisorPath()
	if err != nil {
		return LaunchResult{}, err
	}
	// Launch is also a public entry point. Repeat the engine/image proof here so
	// callers cannot bypass it by skipping HostRunner's capability check.
	if _, err := h.Capabilities(ctx); err != nil {
		return LaunchResult{}, err
	}
	connection, err := h.localConnection()
	if err != nil {
		return LaunchResult{}, err
	}
	if err := dockerSafePath(spec.TargetRoot); err != nil {
		return LaunchResult{}, fmt.Errorf("target path: %w", err)
	}
	if err := dockerSafePath(spec.TemporaryDir); err != nil {
		return LaunchResult{}, fmt.Errorf("temporary path: %w", err)
	}
	if err := dockerSafePath(spec.ToolPath); err != nil {
		return LaunchResult{}, fmt.Errorf("tool path: %w", err)
	}
	if !spec.verifiedInputs && spec.ToolDigest != "" {
		if err := verifyRegularFileDigest(spec.ToolPath, spec.ToolDigest); err != nil {
			return LaunchResult{}, fmt.Errorf("tool changed before Docker launch: %w", err)
		}
	}
	if spec.InputPath != "" {
		if err := dockerSafePath(spec.InputPath); err != nil {
			return LaunchResult{}, fmt.Errorf("input path: %w", err)
		}
		info, err := os.Lstat(spec.InputPath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return LaunchResult{}, errors.New("declared input must be a regular non-symlink file")
		}
	}
	if spec.DatabasePath != "" {
		if err := dockerSafePath(spec.DatabasePath); err != nil {
			return LaunchResult{}, fmt.Errorf("database path: %w", err)
		}
		if !spec.verifiedInputs {
			if err := VerifyDatabaseSnapshot(spec.DatabasePath, spec.DatabaseDigest, spec.AdapterID); err != nil {
				return LaunchResult{}, fmt.Errorf("database snapshot: %w", err)
			}
		}
	}
	if spec.StatePath != "" {
		if err := dockerSafePath(spec.StatePath); err != nil {
			return LaunchResult{}, fmt.Errorf("prepared state path: %w", err)
		}
		if !spec.verifiedInputs {
			if err := VerifyPreparedState(spec.StatePath, spec.StateDigest, spec.AdapterID); err != nil {
				return LaunchResult{}, fmt.Errorf("prepared state: %w", err)
			}
		}
	}
	if spec.RulePackPath != "" {
		if err := dockerSafePath(spec.RulePackPath); err != nil {
			return LaunchResult{}, fmt.Errorf("rule-pack path: %w", err)
		}
		if !spec.verifiedInputs {
			if err := VerifyInputCapsule(spec.RulePackPath, spec.RulePackDigest, spec.AdapterID, "rule-pack"); err != nil {
				return LaunchResult{}, fmt.Errorf("rule pack: %w", err)
			}
		}
	}
	if isInsidePath(spec.TargetRoot, spec.ToolPath) {
		return LaunchResult{}, errors.New("tool path must not be inside the untrusted target")
	}

	toolDirectory := filepath.Dir(spec.ToolPath)
	toolInContainer := "/pao/tool/" + filepath.Base(spec.ToolPath)
	entrypointInContainer := toolInContainer
	if spec.StateEntrypoint != "" {
		entrypointInContainer = "/pao/state/" + spec.StateEntrypoint
	}
	outputHostPath := ""
	outputInContainer := ""
	inputInContainer := ""
	if spec.InputPath != "" {
		inputInContainer = "/pao/input/" + filepath.Base(spec.InputPath)
	}
	if spec.OutputFile != "" {
		outputHostPath = filepath.Join(spec.TemporaryDir, filepath.FromSlash(spec.OutputFile))
		outputInContainer = "/pao/out/" + spec.OutputFile
	}
	args, err := mapArguments(spec.Arguments, spec.TargetRoot, spec.TemporaryDir, spec.ToolPath, toolInContainer, spec.InputPath, inputInContainer, spec.DatabasePath, spec.RulePackPath, outputHostPath, outputInContainer, spec.AdditionalOutputs)
	if err != nil {
		return LaunchResult{}, err
	}
	memoryMB := spec.MemoryMB
	if memoryMB == 0 {
		memoryMB = 1024
	}
	request := sandbox.Request{Version: sandbox.Version, Entrypoint: entrypointInContainer, Arguments: args, MaxBytes: outputBudget(spec)}
	if spec.OutputFile != "" {
		request.Files = append(request.Files, spec.OutputFile)
	}
	for _, output := range spec.AdditionalOutputs {
		request.Files = append(request.Files, output.File)
	}
	if err := request.Validate(); err != nil {
		return LaunchResult{}, err
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return LaunchResult{}, err
	}
	if len(requestJSON) > 96<<10 {
		return LaunchResult{}, errors.New("supervisor request exceeds its limit")
	}
	if err := h.RuntimeApproval.Validate(h.currentTime()); err != nil {
		return LaunchResult{}, err
	}
	dockerArgs := []string{
		"run", "--rm",
		"--pull", "never",
		"--log-driver", "none",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(pidsLimit),
		"--memory", strconv.Itoa(memoryMB) + "m",
		"--cpus", "1.0",
		"--user", connection.user,
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,nr_inodes=4096",
		"--tmpfs", "/pao/out:rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(scratchBudget(spec), 10) + ",nr_inodes=4096,mode=1777",
		"--mount", dockerReadOnlyMount(supervisor, "/pao/core/sandbox"),
		"--mount", dockerReadOnlyMount(toolDirectory, "/pao/tool"),
	}
	// The quality adapter consumes captured evidence only; it has no reason to
	// see source files, even through a read-only target mount.
	if spec.AdapterID != "sbomqs" {
		dockerArgs = append(dockerArgs, "--mount", dockerReadOnlyMount(spec.TargetRoot, "/pao/target"))
	}
	if spec.ContainerName != "" {
		dockerArgs = append(dockerArgs, "--name", spec.ContainerName)
	}
	if spec.StatePath != "" {
		dockerArgs = append(dockerArgs, "--mount", dockerReadOnlyMount(spec.StatePath, "/pao/state"))
	}
	if spec.InputPath != "" {
		dockerArgs = append(dockerArgs, "--mount", dockerReadOnlyMount(spec.InputPath, inputInContainer))
	}
	if spec.DatabasePath != "" {
		dockerArgs = append(dockerArgs, "--mount", dockerReadOnlyMount(spec.DatabasePath, "/pao/database"))
	}
	if spec.RulePackPath != "" {
		dockerArgs = append(dockerArgs, "--mount", dockerReadOnlyMount(spec.RulePackPath, "/pao/rules"))
	}
	for name, value := range spec.Environment {
		dockerArgs = append(dockerArgs, "--env", name+"="+value)
	}
	dockerArgs = append(dockerArgs, "--entrypoint", "/pao/core/sandbox", h.RuntimeImage, base64.RawURLEncoding.EncodeToString(requestJSON))
	if spec.launchAdmission != nil {
		if err := spec.launchAdmission(); err != nil {
			return LaunchResult{}, err
		}
	}
	captured, commandErr := h.launchCommand(ctx, dockerArgs...)
	if h.syntheticEnvelope != nil {
		captured, commandErr = h.syntheticEnvelope(spec, captured, commandErr)
	}
	if ctx.Err() != nil || commandErr != nil {
		if err := h.cleanupContainer(spec.ContainerName); err != nil {
			return LaunchResult{Status: Failed, DiagnosticCode: "CONTAINER_CLEANUP_UNCONFIRMED", Reason: "container teardown could not be confirmed", MediaType: dockerRawMediaType, Stderr: captured.stderr, StderrTruncated: captured.stderrTruncated}, &UnconfirmedContainerCleanupError{ContainerName: spec.ContainerName, Cause: err}
		}
	}
	envelope, outputErr := sandbox.Decode(captured.stdout, request)
	result := LaunchResult{Stderr: captured.stderr, StderrTruncated: captured.stderrTruncated}
	evidence, mediaType := []byte(nil), dockerRawMediaType
	if outputErr == nil && !captured.stdoutTruncated {
		result.Stderr, result.StderrTruncated = envelope.Stderr, envelope.StderrTruncated
		result.StdoutTruncated, result.ExitCode = envelope.StdoutTruncated || envelope.OutputLimited, envelope.ExitCode
		evidence = envelope.Stdout
		if spec.OutputFile != "" {
			var present bool
			evidence, present = envelope.Files[spec.OutputFile]
			mediaType = spec.OutputMediaType
			if !present {
				outputErr = errors.New("declared result missing")
			}
		}
		if len(envelope.UnsafeFiles) != 0 {
			outputErr = errors.New("unsafe declared result")
		}
		if h.syntheticEnvelope == nil && outputErr == nil {
			for _, output := range spec.AdditionalOutputs {
				contents, present := envelope.Files[output.File]
				if !present {
					outputErr = errors.New("additional result missing")
					break
				}
				if err := persistTransferredOutput(spec.TemporaryDir, output.File, contents); err != nil {
					outputErr = err
					break
				}
			}
		}
	} else {
		outputErr = errors.New("invalid or oversized supervisor envelope")
	}
	usableResult := outputErr == nil && len(evidence) > 0
	result.RawOutput, result.MediaType = evidence, mediaType
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		result.Status, result.DiagnosticCode, result.Reason = TimedOut, "TIMED_OUT", "container-vm host timed out"
	case ctx.Err() != nil:
		result.Status, result.DiagnosticCode, result.Reason = Failed, "CANCELLED", "container-vm execution cancelled"
	case commandErr != nil && !isExitError(commandErr):
		result.Status, result.DiagnosticCode, result.Reason = Failed, "HOST_START_FAILED", "Docker launch failed"
	case envelope.StartFailed:
		result.Status, result.DiagnosticCode, result.Reason = Failed, "SCANNER_FAILED", "tool or isolated process tree did not complete inside the container-vm"
	case envelope.OutputLimited:
		result.Status, result.DiagnosticCode, result.Reason = Partial, "OUTPUT_LIMIT", "declared output exceeded its aggregate limit"
	case outputErr != nil || !usableResult:
		result.Status, result.DiagnosticCode, result.Reason = Failed, "OUTPUT_MISSING_OR_UNSAFE", "declared scanner result is missing, empty or unsafe"
	case commandErr != nil || result.ExitCode == nil || (*result.ExitCode != 0 && !containsExitCode(spec.successExitCodes, *result.ExitCode)):
		result.Status, result.DiagnosticCode, result.Reason = Failed, "SCANNER_FAILED", "tool exited unsuccessfully inside the container-vm"
	case *result.ExitCode != 0:
		result.Status, result.DiagnosticCode, result.Reason = Succeeded, "FINDINGS_REPORTED", "tool completed inside the container-vm with reportable findings"
	default:
		result.Status, result.DiagnosticCode, result.Reason = Succeeded, "COMPLETED", "tool completed inside the container-vm"
	}
	if (result.StderrTruncated || result.StdoutTruncated) && result.Status == Succeeded {
		result.Status, result.DiagnosticCode, result.Reason = Partial, "OUTPUT_LIMIT", "captured output exceeded its limit; only a prefix was retained"
	}
	return result, nil
}

func (h DockerHost) cleanupContainer(name string) error {
	if name == "" {
		return errors.New("cannot confirm teardown without a container identity")
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, removalErr := h.command(cleanupCtx, "rm", "--force", name)
	// A failed remove may simply mean --rm already removed the container. The
	// successful exact-name listing is authoritative; a transport error is not.
	output, probeErr := h.command(cleanupCtx, "container", "ls", "--all", "--filter", "name=^/"+regexp.QuoteMeta(name)+"$", "--format", "{{.ID}}")
	if probeErr != nil || len(strings.TrimSpace(string(output))) != 0 {
		return errors.Join(removalErr, probeErr, errors.New("container absence was not confirmed"))
	}
	return nil
}

func (h DockerHost) currentTime() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now().UTC()
}

func (h DockerHost) command(ctx context.Context, args ...string) ([]byte, error) {
	connection, err := h.localConnection()
	if err != nil {
		return nil, err
	}
	args = dockerEndpointArguments(connection, args)
	path := h.DockerPath
	if path == "" {
		path = "docker"
	}
	if h.runDocker != nil {
		return h.runDocker(ctx, path, args...)
	}
	release, err := h.pinCLI(ctx, path)
	if err != nil {
		return nil, err
	}
	defer release()
	output, err := captureCommand(ctx, path, args...)
	if output.stdoutTruncated {
		return nil, errors.New("Docker control response exceeded its capture limit")
	}
	return output.stdout, err
}

func dockerEndpointArguments(connection dockerConnection, args []string) []string {
	return append([]string{"--host", connection.endpoint}, args...)
}

func validateDesktopEngine(output []byte) error {
	var info struct {
		OSType          string
		OperatingSystem string
		Name            string
		KernelVersion   string
		SecurityOptions []string
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return errors.New("Docker Desktop engine identity response is invalid")
	}
	kernel := strings.ToLower(info.KernelVersion)
	if info.OSType != "linux" || info.OperatingSystem != "Docker Desktop" || info.Name != "docker-desktop" ||
		(!strings.Contains(kernel, "linuxkit") && !strings.Contains(kernel, "microsoft-standard-wsl2")) {
		return errors.New("local Docker endpoint did not prove the supported Docker Desktop Linux VM identity")
	}
	for _, option := range info.SecurityOptions {
		name := strings.ToLower(strings.SplitN(option, ",", 2)[0])
		if name == "name=rootless" || name == "name=userns" {
			return errors.New("Docker user-namespace remapping is not supported without separate private-input acceptance evidence")
		}
	}
	return nil
}

func (h DockerHost) verifyCLIForInvocation(path string) error {
	if h.DockerSHA256 == "" {
		return errors.New("Docker CLI requires an absolute path and an approved SHA-256")
	}
	return verifyDockerCLI(path, h.DockerSHA256)
}

func (h DockerHost) supervisorPath() (string, error) {
	if h.runDocker != nil || h.runCaptured != nil {
		return "/synthetic/pao-sandbox", nil
	}
	path, digest := h.SandboxPath, h.SandboxSHA256
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", err
		}
		path = filepath.Join(filepath.Dir(executable), "pao-sandbox-linux-amd64")
		digest = buildinfo.SandboxSHA256
	}
	if err := dockerSafePath(path); err != nil {
		return "", err
	}
	if err := verifyRegularFileDigest(path, digest); err != nil {
		return "", fmt.Errorf("bundled PAO supervisor: %w", err)
	}
	return path, nil
}

func outputBudget(spec ExecutionSpec) int64 {
	if spec.MaxOutputBytes == 0 {
		return maxDeclaredOutputBytes
	}
	return spec.MaxOutputBytes
}

func scratchBudget(spec ExecutionSpec) int64 {
	return max(1<<20, min(sandbox.ScratchBytes, 2*outputBudget(spec)))
}

func containsExitCode(codes []int, wanted int) bool {
	for _, code := range codes {
		if code == wanted {
			return true
		}
	}
	return false
}

func persistTransferredOutput(root, name string, contents []byte) error {
	if err := validateOutputFile(name); err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := auditconfig.CheckPath(path, true); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func validateImageID(image string) error {
	if !sha256Reference.MatchString(image) {
		return errors.New("Docker runtime image must be an exact sha256 image ID")
	}
	return nil
}

func dockerSafePath(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\r\n") {
		return errors.New("path must be absolute and cannot contain a Docker mount delimiter")
	}
	return nil
}

func dockerReadOnlyMount(source, target string) string {
	return "type=bind,src=" + source + ",dst=" + target + ",readonly"
}

func dockerReadWriteMount(source, target string) string {
	return "type=bind,src=" + source + ",dst=" + target
}

func mapArguments(arguments []string, target, temporary, toolPath, toolInContainer, inputPath, inputInContainer, databasePath, rulePackPath, outputHostPath, outputInContainer string, additionalOutputs []DeclaredOutput) ([]string, error) {
	type replacement struct{ host, container string }
	// Map declared output files before their parent directory. Otherwise a
	// Windows child path becomes /pao/out\\file inside the Linux container.
	outputs := make([]replacement, 0, len(additionalOutputs)+1)
	if outputHostPath != "" {
		outputs = append(outputs, replacement{outputHostPath, outputInContainer})
	}
	for _, output := range additionalOutputs {
		outputs = append(outputs, replacement{
			filepath.Join(temporary, filepath.FromSlash(output.File)),
			"/pao/out/" + output.File,
		})
	}
	sort.SliceStable(outputs, func(i, j int) bool { return len(outputs[i].host) > len(outputs[j].host) })
	replacements := append(outputs, []replacement{
		{inputPath, inputInContainer},
		{databasePath, "/pao/database"},
		{rulePackPath, "/pao/rules"},
		{temporary, "/pao/out"},
		{toolPath, toolInContainer},
		{target, "/pao/target"},
	}...)
	mapped := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		value := argument
		mappedDeclaredPath := false
		for _, replacement := range replacements {
			if replacement.host != "" {
				if strings.Contains(value, replacement.host) {
					mappedDeclaredPath = true
				}
				value = strings.ReplaceAll(value, replacement.host, replacement.container)
			}
		}
		// A declared host path is converted to its fixed /pao mount before this
		// check.  It is safe to retain that mapped container path, but a caller
		// cannot introduce an arbitrary absolute host or container path.
		if (filepath.IsAbs(value) || strings.HasPrefix(value, "/") || windowsAbsolutePath.MatchString(value)) && !mappedDeclaredPath {
			return nil, errors.New("adapter argument contains an undeclared absolute host path")
		}
		mapped = append(mapped, value)
	}
	return mapped, nil
}

func declaredOutput(spec ExecutionSpec, stdout []byte) ([]byte, string, error) {
	if spec.OutputFile == "" {
		return stdout, dockerRawMediaType, nil
	}
	contents, err := readDeclaredOutput(spec.TemporaryDir, spec.OutputFile)
	if err != nil {
		return nil, "", err
	}
	return contents, spec.OutputMediaType, nil
}

// Use one bounded reader for primary and additional output artifacts. Reject
// redirected parent directories as well as linked/nonregular final files.
func readDeclaredOutput(root, name string) ([]byte, error) {
	if err := validateOutputFile(name); err != nil {
		return nil, err
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := auditconfig.CheckPath(path, false); err != nil {
		return nil, errors.New("declared scanner output path is missing or redirected")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("declared scanner output is missing or unsafe")
	}
	if info.Size() > maxDeclaredOutputBytes {
		return nil, fmt.Errorf("declared scanner output exceeds %d bytes", maxDeclaredOutputBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open declared scanner output: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errors.New("declared scanner output changed before reading")
	}
	contents, err := readOutputBytes(file, opened.Size(), maxDeclaredOutputBytes)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("declared scanner output changed while reading")
	}
	if err := auditconfig.CheckPath(path, false); err != nil {
		return nil, errors.New("declared scanner output path changed while reading")
	}
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, final) {
		return nil, errors.New("declared scanner output was replaced while reading")
	}
	return contents, nil
}

func readOutputBytes(reader io.Reader, expected, limit int64) ([]byte, error) {
	if expected < 0 || expected > limit {
		return nil, errors.New("declared scanner output exceeds its capture limit")
	}
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read declared scanner output: %w", err)
	}
	if int64(len(contents)) > limit || int64(len(contents)) != expected {
		return nil, errors.New("declared scanner output grew, shrank or exceeded its capture limit")
	}
	return contents, nil
}

func isInsidePath(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type exitCoder interface{ ExitCode() int }

func isExitError(err error) bool {
	var exit exitCoder
	return errors.As(err, &exit) && exit.ExitCode() != 0
}

func exitCodeLabel(err error) string {
	var exit exitCoder
	if errors.As(err, &exit) {
		return fmt.Sprintf("exit code %d", exit.ExitCode())
	}
	return "non-zero exit"
}

func acceptedExitCode(err error, accepted []int) bool {
	var exit exitCoder
	if !errors.As(err, &exit) {
		return false
	}
	for _, code := range accepted {
		if exit.ExitCode() == code {
			return true
		}
	}
	return false
}

func exitStderr(err error) []byte {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.Stderr
	}
	return nil
}
