// Package runner validates host-owned, declarative scanner invocation requests.
package runner

import (
	"errors"
	"fmt"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

const StrongIsolation = "container-vm"

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
var containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

var shellExecutables = map[string]struct{}{
	"cmd": {}, "cmd.exe": {}, "powershell": {}, "powershell.exe": {}, "pwsh": {}, "pwsh.exe": {}, "sh": {}, "bash": {}, "zsh": {},
}

type SandboxProperties struct {
	Isolation             string `json:"isolation"`
	RepositoryReadOnly    bool   `json:"repository_read_only"`
	TemporaryWriteOnly    bool   `json:"temporary_write_only"`
	NetworkDenied         bool   `json:"network_denied"`
	EnvironmentSanitized  bool   `json:"environment_sanitized"`
	ProcessTreeControlled bool   `json:"process_tree_controlled"`
	CPULimited            bool   `json:"cpu_limited"`
	MemoryLimited         bool   `json:"memory_limited"`
	FilesystemIsolated    bool   `json:"filesystem_isolated"`
	CleanRuntime          bool   `json:"clean_runtime"`
}

func (s SandboxProperties) Validate() error {
	if s.Isolation != StrongIsolation {
		return fmt.Errorf("isolation mismatch: required %q, got %q", StrongIsolation, s.Isolation)
	}
	if !s.RepositoryReadOnly || !s.TemporaryWriteOnly || !s.NetworkDenied || !s.EnvironmentSanitized || !s.ProcessTreeControlled || !s.CPULimited || !s.MemoryLimited || !s.FilesystemIsolated || !s.CleanRuntime {
		return errors.New("all strong-isolation sandbox properties are required")
	}
	return nil
}

// ExecutionSpec is a data-only invocation request. It intentionally has no shell string,
// inherited environment, target write permission, or adapter-owned launch method.
type ExecutionSpec struct {
	APIVersion        string            `json:"api_version"`
	AdapterID         string            `json:"adapter_id"`
	ToolID            string            `json:"tool_id"`
	ToolPath          string            `json:"tool_path"`
	ToolDigest        string            `json:"tool_digest,omitempty"`
	InputPath         string            `json:"input_path,omitempty"`
	InputDigest       string            `json:"input_digest,omitempty"`
	DatabasePath      string            `json:"database_path,omitempty"`
	DatabaseDigest    string            `json:"database_digest,omitempty"`
	StatePath         string            `json:"state_path,omitempty"`
	StateDigest       string            `json:"state_digest,omitempty"`
	StateEntrypoint   string            `json:"state_entrypoint,omitempty"`
	RuntimeDigest     string            `json:"runtime_digest,omitempty"`
	RulePackPath      string            `json:"rule_pack_path,omitempty"`
	RulePackDigest    string            `json:"rule_pack_digest,omitempty"`
	LicenseDataDigest string            `json:"license_data_digest,omitempty"`
	OutputFile        string            `json:"output_file,omitempty"`
	OutputMediaType   string            `json:"output_media_type,omitempty"`
	AdditionalOutputs []DeclaredOutput  `json:"additional_outputs,omitempty"`
	Arguments         []string          `json:"arguments"`
	TargetRoot        string            `json:"target_root"`
	TemporaryDir      string            `json:"temporary_dir"`
	Environment       map[string]string `json:"environment"`
	TimeoutSeconds    int               `json:"timeout_seconds"`
	MaxOutputBytes    int64             `json:"max_output_bytes,omitempty"`
	MemoryMB          int               `json:"memory_mb,omitempty"`
	ContainerName     string            `json:"container_name,omitempty"`
	Sandbox           SandboxProperties `json:"sandbox"`
	verifiedInputs    bool
	launchAdmission   func() error // trusted host-owned final freshness check, never JSON authority
	successExitCodes  []int
}

// DeclaredOutput is an additional, named raw artifact the host may persist. It
// is deliberately declarative: unlisted temporary files are never evidence.
type DeclaredOutput struct {
	File      string `json:"file"`
	MediaType string `json:"media_type"`
}

func (s ExecutionSpec) Validate() error {
	if s.APIVersion != "pao.dev/execution/v1alpha1" || s.AdapterID == "" || s.ToolID == "" {
		return errors.New("execution spec requires api_version, adapter_id and tool_id")
	}
	if !filepath.IsAbs(s.ToolPath) || !filepath.IsAbs(s.TargetRoot) || !filepath.IsAbs(s.TemporaryDir) {
		return errors.New("tool path, target root and temporary directory must be absolute")
	}
	if _, isShell := shellExecutables[strings.ToLower(filepath.Base(s.ToolPath))]; isShell {
		return errors.New("shell executables are prohibited in execution specs")
	}
	if s.ToolDigest != "" && !sha256Reference.MatchString(s.ToolDigest) {
		return errors.New("tool digest must be an exact SHA-256 reference")
	}
	if target.IsInside(s.TargetRoot, s.TemporaryDir) {
		return errors.New("temporary directory must not be inside target root")
	}
	if s.InputPath != "" {
		if s.InputDigest != "" && !sha256Reference.MatchString(s.InputDigest) {
			return errors.New("input digest must be an exact SHA-256 reference")
		}
		if !filepath.IsAbs(s.InputPath) || target.IsInside(s.TargetRoot, s.InputPath) {
			return errors.New("input path must be absolute and outside the target")
		}
	}
	if s.InputPath == "" && s.InputDigest != "" {
		return errors.New("input digest requires a declared input")
	}
	if s.AdapterID == "sbomqs" && s.InputPath == "" {
		return errors.New("sbomqs requires an explicit captured input file")
	}
	if (s.DatabasePath == "") != (s.DatabaseDigest == "") {
		return errors.New("database path and digest must be supplied together")
	}
	if s.DatabasePath != "" {
		if !filepath.IsAbs(s.DatabasePath) || !sha256Reference.MatchString(s.DatabaseDigest) {
			return errors.New("database requires an absolute path and SHA-256 digest")
		}
		if target.IsInside(s.TargetRoot, s.DatabasePath) || target.IsInside(s.TemporaryDir, s.DatabasePath) || target.IsInside(filepath.Dir(s.ToolPath), s.DatabasePath) {
			return errors.New("database must be separate from target, temporary and tool directories")
		}
	}
	if (s.StatePath == "") != (s.StateDigest == "") {
		return errors.New("prepared state path and digest must be supplied together")
	}
	if s.StatePath != "" {
		if !filepath.IsAbs(s.StatePath) || !sha256Reference.MatchString(s.StateDigest) {
			return errors.New("prepared state requires an absolute path and SHA-256 digest")
		}
		if target.IsInside(s.TargetRoot, s.StatePath) || target.IsInside(s.TemporaryDir, s.StatePath) || target.IsInside(filepath.Dir(s.ToolPath), s.StatePath) {
			return errors.New("prepared state must be separate from target, temporary and tool directories")
		}
	}
	if s.StateEntrypoint != "" {
		if s.StatePath == "" {
			return errors.New("prepared-state entrypoint requires prepared state")
		}
		if err := validateStateEntrypoint(s.StateEntrypoint); err != nil {
			return err
		}
	}
	if s.RuntimeDigest != "" && !sha256Reference.MatchString(s.RuntimeDigest) {
		return errors.New("runtime requires an exact SHA-256 digest")
	}
	if (s.RulePackPath == "") != (s.RulePackDigest == "") {
		return errors.New("rule-pack path and digest must be supplied together")
	}
	if s.RulePackPath != "" {
		if !filepath.IsAbs(s.RulePackPath) || !sha256Reference.MatchString(s.RulePackDigest) {
			return errors.New("rule pack requires an absolute path and SHA-256 digest")
		}
		if target.IsInside(s.TargetRoot, s.RulePackPath) || target.IsInside(s.TemporaryDir, s.RulePackPath) || target.IsInside(filepath.Dir(s.ToolPath), s.RulePackPath) || (s.StatePath != "" && target.IsInside(s.StatePath, s.RulePackPath)) {
			return errors.New("rule pack must be separate from target, temporary, tool and state directories")
		}
	}
	if s.LicenseDataDigest != "" && !sha256Reference.MatchString(s.LicenseDataDigest) {
		return errors.New("license data requires an exact SHA-256 digest")
	}
	if (s.OutputFile == "") != (s.OutputMediaType == "") {
		return errors.New("output file and media type must be supplied together")
	}
	if s.OutputFile != "" {
		if err := validateOutputFile(s.OutputFile); err != nil {
			return err
		}
		if strings.ContainsRune(s.OutputMediaType, '\x00') {
			return errors.New("output media type contains NUL")
		}
	}
	seenOutputs := map[string]bool{}
	if len(s.AdditionalOutputs) > 15 {
		return errors.New("at most 16 declared output files are permitted")
	}
	if s.OutputFile != "" {
		seenOutputs[s.OutputFile] = true
	}
	for _, output := range s.AdditionalOutputs {
		if err := validateOutputFile(output.File); err != nil || output.MediaType == "" || strings.ContainsRune(output.MediaType, '\x00') || seenOutputs[output.File] {
			return errors.New("additional outputs must have unique safe files and media types")
		}
		seenOutputs[output.File] = true
	}
	if s.TimeoutSeconds <= 0 || s.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds must be within 1..3600")
	}
	if s.MaxOutputBytes < 0 || s.MaxOutputBytes > maxDeclaredOutputBytes {
		return errors.New("max_output_bytes must be zero or within 1..67108864")
	}
	if s.MemoryMB != 0 && (s.MemoryMB < 256 || s.MemoryMB > 4096) {
		return errors.New("memory_mb must be zero or within 256..4096")
	}
	if s.ContainerName != "" && !containerName.MatchString(s.ContainerName) {
		return errors.New("container_name contains unsafe characters or has an invalid length")
	}
	if len(s.Arguments) == 0 {
		return errors.New("fixed argument vector is required")
	}
	for _, arg := range s.Arguments {
		if arg == "" || strings.ContainsRune(arg, '\x00') {
			return errors.New("arguments must be non-empty and contain no NUL")
		}
	}
	for name, value := range s.Environment {
		if !environmentName.MatchString(name) || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("unsafe environment allowlist entry: %q", name)
		}
	}
	return s.Sandbox.Validate()
}

// validateStateEntrypoint accepts only a canonical, relative POSIX path within
// the already verified prepared-state capsule. The host prefixes it with
// /pao/state and never accepts an adapter-supplied absolute command path.
func validateStateEntrypoint(entrypoint string) error {
	if strings.ContainsRune(entrypoint, '\x00') || strings.Contains(entrypoint, "\\") || strings.HasPrefix(entrypoint, "/") {
		return errors.New("prepared-state entrypoint must be a relative POSIX path")
	}
	clean := pathpkg.Clean(entrypoint)
	if entrypoint == "." || entrypoint != clean || strings.HasPrefix(clean, "../") {
		return errors.New("prepared-state entrypoint must remain inside prepared state")
	}
	return nil
}

func validateOutputFile(output string) error {
	if strings.ContainsRune(output, '\x00') || strings.Contains(output, "\\") || strings.HasPrefix(output, "/") {
		return errors.New("output file must be a relative POSIX path")
	}
	clean := pathpkg.Clean(output)
	if output == "." || output != clean || strings.HasPrefix(clean, "../") {
		return errors.New("output file must remain inside the temporary output directory")
	}
	return nil
}
