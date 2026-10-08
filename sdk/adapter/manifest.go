package adapter

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const ManifestVersion = "pao.dev/adapter/v1alpha2"

var manifestID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type Manifest struct {
	APIVersion             string   `json:"api_version"`
	ID                     string   `json:"id"`
	DisplayName            string   `json:"display_name"`
	Upstream               string   `json:"upstream"`
	Capabilities           []string `json:"capabilities"`
	SupportedPlatforms     []string `json:"supported_platforms"`
	InputKinds             []string `json:"input_kinds"`
	OutputKinds            []string `json:"output_kinds"`
	SourceLicense          string   `json:"source_license"`
	Redistribution         string   `json:"redistribution"`
	Network                string   `json:"network"`
	WritesTarget           bool     `json:"writes_target"`
	ExecutesTargetCode     bool     `json:"executes_target_code"`
	TimeoutSeconds         int      `json:"timeout_seconds"`
	InputIndicators        []string `json:"input_indicators,omitempty"`
	ParserSchema           string   `json:"parser_schema"`
	CompatibleToolVersions []string `json:"compatible_tool_versions,omitempty"`
	FixedArguments         []string `json:"fixed_arguments"`
	AllowedEnvironment     []string `json:"allowed_environment,omitempty"`
	SuccessExitCodes       []int    `json:"success_exit_codes,omitempty"`
	RequiredSandbox        []string `json:"required_sandbox"`
	PrerequisiteKinds      []string `json:"prerequisite_kinds"`
	FixtureCases           []string `json:"fixture_cases"`
	MaxOutputBytes         int64    `json:"max_output_bytes"`
	RedactionClass         string   `json:"redaction_class"`
	Limitations            []string `json:"limitations,omitempty"`
}

func (m Manifest) Validate() error {
	if m.APIVersion != ManifestVersion || !manifestID.MatchString(m.ID) || m.DisplayName == "" || m.Upstream == "" {
		return errors.New("manifest requires api_version, id and display_name")
	}
	if len(m.Capabilities) == 0 || len(m.SupportedPlatforms) == 0 || len(m.InputKinds) == 0 || len(m.OutputKinds) == 0 || m.SourceLicense == "" || m.Redistribution == "" {
		return errors.New("manifest requires capabilities, platforms, inputs, outputs and license governance")
	}
	if m.Network != "never-during-audit" || m.WritesTarget || m.ExecutesTargetCode {
		return errors.New("manifest violates audit-only safety defaults")
	}
	if m.TimeoutSeconds <= 0 || m.MaxOutputBytes <= 0 || m.ParserSchema == "" || m.RedactionClass == "" {
		return errors.New("manifest requires positive limits, parser schema and redaction class")
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{"capabilities", m.Capabilities}, {"supported_platforms", m.SupportedPlatforms},
		{"input_kinds", m.InputKinds}, {"output_kinds", m.OutputKinds},
		{"fixed_arguments", m.FixedArguments}, {"required_sandbox", m.RequiredSandbox},
		{"prerequisite_kinds", m.PrerequisiteKinds}, {"fixture_cases", m.FixtureCases},
	} {
		if len(field.values) == 0 {
			return fmt.Errorf("manifest requires nonempty %s", field.name)
		}
		for _, value := range field.values {
			if value == "" {
				return fmt.Errorf("manifest %s must contain nonempty strings", field.name)
			}
		}
	}
	if !containsAll(m.RequiredSandbox, []string{"container-vm", "repository-read-only", "temporary-write-only", "network-denied", "environment-sanitized", "process-tree-controlled", "cpu-limited", "memory-limited", "filesystem-isolated", "clean-runtime"}) {
		return errors.New("manifest requires every strong-isolation property")
	}
	if !containsAll(m.FixtureCases, []string{"success", "empty", "partial", "error", "malformed"}) {
		return errors.New("manifest requires complete synthetic fixture matrix")
	}
	if len(m.FixedArguments) == 0 || containsShell(m.FixedArguments) {
		return errors.New("manifest requires fixed non-shell argument tokens")
	}
	if err := validateSuccessExitCodes(m.SuccessExitCodes); err != nil {
		return err
	}
	seenVersions := make(map[string]bool, len(m.CompatibleToolVersions))
	for _, version := range m.CompatibleToolVersions {
		if strings.TrimSpace(version) == "" || version != strings.TrimSpace(version) || strings.ContainsAny(version, "\x00\r\n") || seenVersions[version] {
			return errors.New("compatible tool versions must be unique nonempty exact version strings")
		}
		seenVersions[version] = true
	}
	for _, indicator := range m.InputIndicators {
		if indicator == "" || filepath.IsAbs(indicator) || strings.Contains(indicator, "..") || strings.ContainsRune(indicator, '\x00') {
			return fmt.Errorf("unsafe input indicator: %q", indicator)
		}
	}
	return m.AllowsEnvironment(nil)
}

// AllowsToolVersion binds a parser declaration to an exact compatibility list.
// An older manifest may still be read for inspection, but cannot authorize a
// parser launch without an explicit version. Binary identity is not support.
func (m Manifest) AllowsToolVersion(version string) error {
	if len(m.CompatibleToolVersions) == 0 {
		return errors.New("tool version compatibility is not declared")
	}
	for _, compatible := range m.CompatibleToolVersions {
		if compatible == version {
			return nil
		}
	}
	return errors.New("tool version is outside the manifest parser compatibility contract")
}

func validateSuccessExitCodes(codes []int) error {
	if len(codes) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(codes))
	for _, code := range codes {
		if code < 0 || code > 255 {
			return errors.New("success exit codes must be within 0..255")
		}
		if _, exists := seen[code]; exists {
			return errors.New("success exit codes must not contain duplicates")
		}
		seen[code] = struct{}{}
	}
	if _, exists := seen[0]; !exists {
		return errors.New("success exit codes must include zero")
	}
	return nil
}

// AllowsEnvironment verifies that an execution supplies only manifest-declared,
// data-only environment entries. Missing declared entries are permitted here;
// adapter-specific toolchain records may require an exact environment separately.
func (m Manifest) AllowsEnvironment(environment map[string]string) error {
	allowed := make(map[string]struct{}, len(m.AllowedEnvironment))
	for _, name := range m.AllowedEnvironment {
		if !environmentName.MatchString(name) {
			return fmt.Errorf("unsafe allowed environment name: %q", name)
		}
		if _, exists := allowed[name]; exists {
			return fmt.Errorf("duplicate allowed environment name: %q", name)
		}
		allowed[name] = struct{}{}
	}
	for name, value := range environment {
		if _, permitted := allowed[name]; !permitted || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("environment entry is not allowed by manifest: %q", name)
		}
	}
	return nil
}

func containsAll(values, required []string) bool {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	for _, want := range required {
		found := false
		for _, value := range copy {
			found = found || value == want
		}
		if !found {
			return false
		}
	}
	return true
}

func containsShell(arguments []string) bool {
	for _, argument := range arguments {
		name := strings.ToLower(filepath.Base(argument))
		if name == "cmd" || name == "cmd.exe" || name == "powershell" || name == "powershell.exe" || name == "pwsh" || name == "pwsh.exe" || name == "sh" || name == "bash" {
			return true
		}
	}
	return false
}
