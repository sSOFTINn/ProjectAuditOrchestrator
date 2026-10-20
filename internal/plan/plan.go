package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/detect"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type AdapterNode struct {
	ID                    string   `json:"id"`
	Capability            string   `json:"capability"`
	Status                string   `json:"status"`
	Command               []string `json:"command,omitempty"`
	Network               string   `json:"network"`
	WritesTarget          bool     `json:"writes_target"`
	ExecutesTargetCode    bool     `json:"executes_target_code"`
	ToolDigest            string   `json:"tool_digest"`
	ManifestDigest        string   `json:"manifest_digest"`
	ConfigDigest          string   `json:"config_digest"`
	StateDigest           string   `json:"state_digest,omitempty"`
	RuntimeDigest         string   `json:"runtime_digest,omitempty"`
	RulePackDigest        string   `json:"rule_pack_digest,omitempty"`
	LicenseDataDigest     string   `json:"license_data_digest,omitempty"`
	Inputs                []string `json:"inputs"`
	Outputs               []string `json:"outputs"`
	CoverageStatus        string   `json:"coverage_status"`
	Applicability         string   `json:"applicability,omitempty"`
	SupportStatus         string   `json:"support_status,omitempty"`
	SupportReasons        []string `json:"support_reason_codes,omitempty"`
	SupportedEcosystems   []string `json:"supported_ecosystems,omitempty"`
	UnsupportedEcosystems []string `json:"unsupported_ecosystems,omitempty"`
	Limitations           []string `json:"limitations,omitempty"`
	Sandbox               Sandbox  `json:"sandbox"`
}

// Sandbox is a declarative launch requirement, not proof that a host can meet it.
// A runner must refuse an adapter when any required property is unavailable.
type Sandbox struct {
	Isolation             string `json:"isolation"`
	Network               string `json:"network"`
	TargetAccess          string `json:"target_access"`
	TemporaryWriteOnly    bool   `json:"temporary_write_only"`
	EnvironmentSanitized  bool   `json:"environment_sanitized"`
	ProcessTreeControlled bool   `json:"process_tree_controlled"`
	CPULimited            bool   `json:"cpu_limited"`
	MemoryLimited         bool   `json:"memory_limited"`
	CleanRuntime          bool   `json:"clean_runtime"`
}

type Plan struct {
	Version              string        `json:"version"`
	Profile              string        `json:"profile"`
	TargetID             string        `json:"target_id"`
	Detected             detect.Result `json:"detected"`
	RequiredCapabilities []string      `json:"required_capabilities"`
	Nodes                []AdapterNode `json:"nodes"`
	Network              string        `json:"network"`
	WritesTarget         bool          `json:"writes_target"`
	ExecutesTargetCode   bool          `json:"executes_target_code"`
	DryRun               bool          `json:"dry_run"`
	Inputs               []string      `json:"inputs"`
	Outputs              []string      `json:"outputs"`
	Sandbox              Sandbox       `json:"sandbox"`
	CoverageStatus       string        `json:"coverage_status"`
	PlanDigest           string        `json:"plan_digest"`
	ConfigurationDigest  string        `json:"configuration_digest,omitempty"`
}

// BuildConfiguredFromManifests binds an explicit operator profile and its canonical
// configuration to the selected declarations. PATH availability is not execution proof.
func BuildConfiguredFromManifests(s target.Snapshot, profile, configurationDigest string, manifests []adapter.Manifest) (Plan, error) {
	if profile == "" || !strings.HasPrefix(configurationDigest, "sha256:") || len(configurationDigest) != 71 {
		return Plan{}, errors.New("explicit profile and configuration SHA-256 are required")
	}
	if _, err := hex.DecodeString(configurationDigest[7:]); err != nil {
		return Plan{}, err
	}
	p, err := BuildMVPFromManifests(s, false, manifests)
	if err != nil {
		return Plan{}, err
	}
	p.Profile, p.ConfigurationDigest = profile, configurationDigest
	for i := range p.Nodes {
		if p.Nodes[i].Status != "SKIPPED_NOT_APPLICABLE" && p.Nodes[i].Status != "UNSUPPORTED" {
			p.Nodes[i].Status = "PREFLIGHT_REQUIRED"
		}
		p.Nodes[i].ConfigDigest = configDigest(configurationDigest, p.Nodes[i].ConfigDigest)
	}
	p.PlanDigest = digest(p)
	return p, nil
}

func Build(s target.Snapshot, profile string, dryRun bool) Plan {
	p := Plan{Version: "pao.dev/plan/v1alpha1", Profile: profile, TargetID: s.TargetID, Detected: detect.Detect(s), Network: "denied", DryRun: dryRun}
	p.RequiredCapabilities = []string{"repository_read_only", "temporary_write_only", "network_denied", "environment_sanitized", "process_tree_controlled", "cpu_limited", "memory_limited", "filesystem_isolated", "clean_runtime"}
	p.Inputs = []string{"target_snapshot", "verified_toolchain_record", "adapter_manifest", "profile_configuration"}
	p.Outputs = []string{"plan.lock.json", "tool_execution_record", "coverage_record", "protected_raw_artifact"}
	p.Sandbox = requiredSandbox()
	p.CoverageStatus = "PARTIAL"
	if profile == "fast" || profile == "" {
		p.Profile = "fast"
		p.Nodes = append(p.Nodes, plannedNode(adapterDefinition{ID: "inventory", Capability: "inventory", Command: "pao-inventory"}, p.Detected))
		p.Nodes = append(p.Nodes, plannedNode(adapterDefinition{ID: "trivy", Capability: "vulnerability", Command: "trivy"}, p.Detected))
	} else if profile == "mvp" {
		for _, definition := range mvpCatalog {
			p.Nodes = append(p.Nodes, plannedNode(definition, p.Detected))
		}
	} else {
		p.Nodes = append(p.Nodes, node("profile-unsupported", "unknown", profile, false))
	}
	p.PlanDigest = digest(p)
	return p
}

// BuildMVPFromManifests builds the M2 profile from validated file-backed declarations.
// It is separate from Build until the CLI obtains an explicit trusted manifest directory.
func BuildMVPFromManifests(s target.Snapshot, dryRun bool, manifests []adapter.Manifest) (Plan, error) {
	if len(manifests) == 0 {
		return Plan{}, errors.New("MVP plan requires adapter manifests")
	}
	p := Build(s, "mvp", dryRun)
	p.Nodes = nil
	seen := map[string]bool{}
	copy := append([]adapter.Manifest(nil), manifests...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].ID < copy[j].ID })
	for _, manifest := range copy {
		if err := manifest.Validate(); err != nil {
			return Plan{}, err
		}
		if seen[manifest.ID] {
			return Plan{}, errors.New("duplicate adapter manifest: " + manifest.ID)
		}
		seen[manifest.ID] = true
		p.Nodes = append(p.Nodes, manifestNode(manifest, p.Detected))
	}
	p.PlanDigest = digest(p)
	return p, nil
}

type adapterDefinition struct {
	ID            string
	Capability    string
	Command       string
	Conditional   string
	RequiresState bool
}

var mvpCatalog = []adapterDefinition{
	{ID: "syft", Capability: "inventory/sbom", Command: "syft"}, {ID: "sbomqs", Capability: "sbom-quality", Command: "sbomqs"}, {ID: "grype", Capability: "vulnerability", Command: "grype"}, {ID: "osv-scanner", Capability: "vulnerability", Command: "osv-scanner"}, {ID: "scancode", Capability: "license", Command: "scancode", RequiresState: true}, {ID: "reuse", Capability: "license-compliance", Command: "reuse"}, {ID: "trivy", Capability: "vulnerability", Command: "trivy"}, {ID: "gitleaks", Capability: "secret", Command: "gitleaks"}, {ID: "opengrep", Capability: "sast", Command: "opengrep", RequiresState: true}, {ID: "zizmor", Capability: "workflow-security", Command: "zizmor", Conditional: "workflow-security-input"},
}

func plannedNode(definition adapterDefinition, detected detect.Result) AdapterNode {
	if definition.Conditional != "" && !hasIndicator(detected, definition.Conditional) {
		return bindSupport(AdapterNode{ID: definition.ID, Capability: definition.Capability, Status: "SKIPPED_NOT_APPLICABLE", Network: "never-during-audit", ToolDigest: "UNVERIFIED", ManifestDigest: configDigest(definition.ID, "manifest"), ConfigDigest: configDigest(definition.ID, definition.Capability), Inputs: []string{"target_snapshot"}, Outputs: []string{"coverage_record"}, CoverageStatus: "PARTIAL", Sandbox: requiredSandbox()}, detected)
	}
	n := node(definition.ID, definition.Capability, definition.Command, definition.RequiresState)
	if requiresCapturedSBOM(definition.ID) {
		n.Inputs = append(n.Inputs, "captured_cyclonedx_sbom")
	}
	if definition.ID == "osv-scanner" {
		n.Limitations = []string{"local-database-currently-covers-go-only", "no-remediation-or-package-manager-execution"}
	}
	return bindSupport(n, detected)
}

func manifestNode(manifest adapter.Manifest, detected detect.Result) AdapterNode {
	digest, err := adapter.Digest(manifest)
	if err != nil {
		return AdapterNode{ID: manifest.ID, Capability: "invalid", Status: "UNAVAILABLE", CoverageStatus: "PARTIAL"}
	}
	capability := strings.Join(manifest.Capabilities, "/")
	if !requiresCapturedSBOM(manifest.ID) && !hasAllIndicators(detected, manifest.InputIndicators) {
		return bindSupport(AdapterNode{ID: manifest.ID, Capability: capability, Status: "SKIPPED_NOT_APPLICABLE", Network: manifest.Network, ToolDigest: "UNVERIFIED", ManifestDigest: digest, ConfigDigest: configDigest(manifest.ID, capability), Inputs: []string{"target_snapshot"}, Outputs: []string{"coverage_record"}, CoverageStatus: "PARTIAL", Limitations: append([]string(nil), manifest.Limitations...), Sandbox: requiredSandbox()}, detected)
	}
	status := "UNAVAILABLE"
	if _, err := exec.LookPath(manifest.ID); err == nil {
		status = "AVAILABLE_NOT_STARTED"
	}
	inputs := []string{"target_snapshot", "verified_toolchain_record"}
	if requiresCapturedSBOM(manifest.ID) {
		// sbomqs is intentionally not selected from target file names. It receives
		// only the CycloneDX artifact captured by the preceding Syft execution.
		inputs = append(inputs, "captured_cyclonedx_sbom")
	}
	stateDigest := ""
	runtimeDigest := ""
	rulePackDigest := ""
	licenseDataDigest := ""
	if requiresPreparedState(manifest.ID) {
		inputs = append(inputs, "verified_prepared_state")
		stateDigest = "UNVERIFIED"
	}
	if manifest.ID == "opengrep" || manifest.ID == "scancode" {
		inputs = append(inputs, "verified_runtime")
		runtimeDigest = "UNVERIFIED"
	}
	if manifest.ID == "opengrep" {
		inputs = append(inputs, "verified_rule_pack")
		rulePackDigest = "UNVERIFIED"
	}
	if manifest.ID == "scancode" {
		inputs = append(inputs, "verified_license_data")
		licenseDataDigest = "UNVERIFIED"
	}
	return bindSupport(AdapterNode{ID: manifest.ID, Capability: capability, Status: status, Command: manifest.FixedArguments, Network: manifest.Network, ToolDigest: "UNVERIFIED", ManifestDigest: digest, ConfigDigest: configDigest(manifest.ID, capability), StateDigest: stateDigest, RuntimeDigest: runtimeDigest, RulePackDigest: rulePackDigest, LicenseDataDigest: licenseDataDigest, Inputs: inputs, Outputs: []string{"tool_execution_record", "coverage_record", "protected_raw_artifact"}, CoverageStatus: "PARTIAL", Limitations: append([]string(nil), manifest.Limitations...), Sandbox: requiredSandbox()}, detected)
}

// bindSupport separates presence of input from the admitted local scanner/feed
// coverage. The currently admitted OSV contract covers Go only: removing a
// limitation from a custom manifest cannot silently expand the approved feed.
func bindSupport(n AdapterNode, detected detect.Result) AdapterNode {
	n.Applicability, n.SupportStatus = "APPLICABLE", "DECLARED"
	if n.Status == "SKIPPED_NOT_APPLICABLE" {
		n.Applicability, n.SupportStatus = "NOT_APPLICABLE", "NOT_APPLICABLE"
	}
	if n.ID == "syft" {
		for _, input := range detected.DependencyInputs {
			if input.Support == detect.UnsupportedFormat {
				n.SupportStatus = "PARTIAL"
				n.SupportReasons = appendUnique(n.SupportReasons, "UNSUPPORTED_INPUT_FORMAT")
			}
		}
	}
	if n.ID != "osv-scanner" {
		return n
	}
	if len(detected.ExpectedEcosystems) == 0 {
		n.Status, n.Applicability, n.SupportStatus = "SKIPPED_NOT_APPLICABLE", "NOT_APPLICABLE", "NOT_APPLICABLE"
		n.Command = nil
		return n
	}
	n.Applicability, n.SupportStatus = "APPLICABLE", "SUPPORTED"
	for _, ecosystem := range detected.ExpectedEcosystems {
		if ecosystem == "Go" {
			n.SupportedEcosystems = append(n.SupportedEcosystems, ecosystem)
		} else {
			n.UnsupportedEcosystems = append(n.UnsupportedEcosystems, ecosystem)
		}
	}
	if len(n.UnsupportedEcosystems) > 0 {
		n.SupportStatus = "PARTIAL"
		n.SupportReasons = append(n.SupportReasons, "DB_ECOSYSTEM_UNSUPPORTED")
	}
	for _, input := range detected.DependencyInputs {
		if input.Support == detect.UnsupportedFormat {
			n.SupportStatus = "PARTIAL"
			n.SupportReasons = appendUnique(n.SupportReasons, "UNSUPPORTED_INPUT_FORMAT")
		}
	}
	if len(n.SupportedEcosystems) == 0 {
		n.Status, n.SupportStatus = "UNSUPPORTED", "UNSUPPORTED"
		n.Command = nil
	}
	return n
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func hasIndicator(result detect.Result, expected string) bool {
	for _, indicator := range result.Indicators {
		if indicator == expected {
			return true
		}
	}
	return false
}

// hasAllIndicators treats manifest input indicators as trusted semantic prerequisites.
// bindSupport separately identifies known present inputs with unsupported local
// feed or format coverage; those must not be described as absent inputs.
func hasAllIndicators(result detect.Result, expected []string) bool {
	for _, indicator := range expected {
		if !hasIndicator(result, indicator) {
			return false
		}
	}
	return true
}

func node(id, capability, command string, requiresState bool) AdapterNode {
	status := "UNAVAILABLE"
	if _, err := exec.LookPath(command); err == nil {
		status = "AVAILABLE_NOT_STARTED"
	}
	inputs := []string{"target_snapshot", "verified_toolchain_record"}
	stateDigest := ""
	if requiresState {
		inputs = append(inputs, "verified_prepared_state")
		stateDigest = "UNVERIFIED"
	}
	return AdapterNode{
		ID: id, Capability: capability, Status: status, Command: []string{command}, Network: "never-during-audit",
		ToolDigest: "UNVERIFIED", ManifestDigest: configDigest(id, "manifest"), ConfigDigest: configDigest(id, capability), StateDigest: stateDigest, Inputs: inputs,
		Outputs: []string{"tool_execution_record", "coverage_record", "protected_raw_artifact"}, CoverageStatus: "PARTIAL", Sandbox: requiredSandbox(),
	}
}

func requiresPreparedState(adapterID string) bool {
	return adapterID == "opengrep" || adapterID == "scancode"
}

func requiresCapturedSBOM(adapterID string) bool { return adapterID == "sbomqs" }

func requiredSandbox() Sandbox {
	return Sandbox{Isolation: "container-vm", Network: "denied", TargetAccess: "read-only", TemporaryWriteOnly: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, CleanRuntime: true}
}

func configDigest(id, capability string) string {
	sum := sha256.Sum256([]byte("pao.dev/adapter-config/v1alpha1\x00" + id + "\x00" + capability))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalJSON returns a stable representation for the lock file. The plan has no maps;
// its remaining order-insensitive lists are sorted before serialization.
func CanonicalJSON(p Plan) ([]byte, error) {
	return canonicalJSON(p, false)
}

// LockJSON is the canonical persisted form of a verified plan. Unlike CanonicalJSON,
// it retains the content-derived plan digest needed to resume and verify the lock.
func LockJSON(p Plan) ([]byte, error) {
	if err := Verify(p); err != nil {
		return nil, err
	}
	return canonicalJSON(p, true)
}

func canonicalJSON(p Plan, retainDigest bool) ([]byte, error) {
	if p.Version != "pao.dev/plan/v1alpha1" || p.TargetID == "" || p.Profile == "" {
		return nil, errors.New("plan is missing required identity fields")
	}
	copy := p
	if !retainDigest {
		copy.PlanDigest = ""
	}
	copy.RequiredCapabilities = append([]string(nil), p.RequiredCapabilities...)
	copy.Inputs = append([]string(nil), p.Inputs...)
	copy.Outputs = append([]string(nil), p.Outputs...)
	copy.Nodes = append([]AdapterNode(nil), p.Nodes...)
	copy.Detected.Languages = append([]string(nil), p.Detected.Languages...)
	copy.Detected.Artifacts = append([]string(nil), p.Detected.Artifacts...)
	copy.Detected.Capabilities = append([]string(nil), p.Detected.Capabilities...)
	copy.Detected.Indicators = append([]string(nil), p.Detected.Indicators...)
	copy.Detected.ExpectedEcosystems = append([]string(nil), p.Detected.ExpectedEcosystems...)
	copy.Detected.DependencyInputs = append([]detect.DependencyInput(nil), p.Detected.DependencyInputs...)
	copy.Detected.EmptyGoModuleHashes = append([]string(nil), p.Detected.EmptyGoModuleHashes...)
	sort.Strings(copy.Detected.EmptyGoModuleHashes)
	sort.Strings(copy.Detected.ExpectedEcosystems)
	sort.Slice(copy.Detected.DependencyInputs, func(i, j int) bool {
		a, b := copy.Detected.DependencyInputs[i], copy.Detected.DependencyInputs[j]
		return a.Ecosystem+"\x00"+a.Format+"\x00"+a.Scope+"\x00"+a.Support < b.Ecosystem+"\x00"+b.Format+"\x00"+b.Scope+"\x00"+b.Support
	})
	sort.Strings(copy.RequiredCapabilities)
	sort.Strings(copy.Inputs)
	sort.Strings(copy.Outputs)
	sort.Slice(copy.Nodes, func(i, j int) bool { return copy.Nodes[i].ID < copy.Nodes[j].ID })
	for i := range copy.Nodes {
		copy.Nodes[i].Command = append([]string(nil), copy.Nodes[i].Command...)
		copy.Nodes[i].Inputs = append([]string(nil), copy.Nodes[i].Inputs...)
		copy.Nodes[i].Outputs = append([]string(nil), copy.Nodes[i].Outputs...)
		copy.Nodes[i].SupportReasons = append([]string(nil), copy.Nodes[i].SupportReasons...)
		copy.Nodes[i].SupportedEcosystems = append([]string(nil), copy.Nodes[i].SupportedEcosystems...)
		copy.Nodes[i].UnsupportedEcosystems = append([]string(nil), copy.Nodes[i].UnsupportedEcosystems...)
		copy.Nodes[i].Limitations = append([]string(nil), copy.Nodes[i].Limitations...)
		sort.Strings(copy.Nodes[i].Inputs)
		sort.Strings(copy.Nodes[i].Outputs)
		sort.Strings(copy.Nodes[i].SupportReasons)
		sort.Strings(copy.Nodes[i].SupportedEcosystems)
		sort.Strings(copy.Nodes[i].UnsupportedEcosystems)
		sort.Strings(copy.Nodes[i].Limitations)
	}
	return json.Marshal(copy)
}

// Verify confirms that a supplied lock plan still matches its content-derived identity.
func Verify(p Plan) error {
	if p.PlanDigest == "" || p.PlanDigest != digest(p) {
		return errors.New("plan digest does not match canonical plan")
	}
	return nil
}

func digest(p Plan) string {
	encoded, err := CanonicalJSON(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
