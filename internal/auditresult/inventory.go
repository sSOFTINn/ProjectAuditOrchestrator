package auditresult

import (
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/detect"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
)

// InventoryCoverage checks whether the parsed Syft inventory accounts for the
// detected dependency ecosystems and known unsupported formats. Adequate is
// deliberately narrower than a full dependency graph: it cannot prove that
// every package, transitive dependency, build extra or runtime is represented.
type InventoryCoverage struct {
	Status             string         `json:"status"`
	Adequate           bool           `json:"adequate_for_detected_inputs"`
	ExpectedEcosystems []string       `json:"expected_ecosystems"`
	ObservedEcosystems []string       `json:"observed_ecosystems"`
	Gaps               []InventoryGap `json:"gaps"`
	Evidence           []string       `json:"evidence_refs,omitempty"`
	Limitations        []string       `json:"limitations"`
}

// All public fields use closed vocabularies; names, versions, custom paths and
// scanner messages stay in the private observations and raw evidence.
type InventoryGap struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Format    string `json:"format,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Reason    string `json:"reason_code"`
}

func nodeCoverage(n plan.AdapterNode) Coverage {
	c := Coverage{Scanner: n.ID, ExecutionStatus: "MISSING", ParsingStatus: "NOT_AVAILABLE", Applicability: "NOT_RECORDED", SupportStatus: "NOT_RECORDED"}
	switch n.Applicability {
	case "APPLICABLE", "NOT_APPLICABLE":
		c.Applicability = n.Applicability
	}
	switch n.SupportStatus {
	case "DECLARED", "SUPPORTED", "PARTIAL", "UNSUPPORTED", "NOT_APPLICABLE":
		c.SupportStatus = n.SupportStatus
	}
	for _, code := range n.SupportReasons {
		switch code {
		case "DB_ECOSYSTEM_UNSUPPORTED", "ECOSYSTEM_UNSUPPORTED", "UNSUPPORTED_INPUT_FORMAT":
			c.SupportReasons = append(c.SupportReasons, code)
		default:
			c.SupportReasons = append(c.SupportReasons, "UNRECOGNIZED_SUPPORT_REASON")
		}
	}
	for _, limitation := range n.Limitations {
		if knownManifestLimitation(limitation) {
			c.Limitations = append(c.Limitations, limitation)
		} else {
			c.Limitations = append(c.Limitations, "unrecognized-manifest-limitation")
		}
	}
	c.SupportReasons, c.Limitations = unique(c.SupportReasons), unique(c.Limitations)
	return c
}

func knownManifestLimitation(value string) bool {
	switch value {
	case "local-database-currently-covers-go-only", "no-remediation-or-package-manager-execution",
		"history-and-directory-coverage-are-distinct", "pao-baseline-v1-is-intentionally-narrow",
		"offline-mode-has-explicit-partial-coverage", "requires-verified-local-database",
		"filesystem-vulnerability-only-no-iac-container-image-or-sarif-coverage", "secret-scan-delegated-to-gitleaks",
		"specialist-license-secret-and-sast-adapters-remain-authoritative", "score-is-informational",
		"requires-owner-approved-local-tool", "compliance-evidence-not-legal-verdict",
		"does-not-assess-vulnerabilities", "license-results-require-human-legal-interpretation":
		return true
	}
	return false
}

func assessInventory(lock plan.Plan, coverage []Coverage, observations []Observation) InventoryCoverage {
	r := InventoryCoverage{Status: "PARTIAL", ExpectedEcosystems: []string{}, ObservedEcosystems: []string{}, Gaps: []InventoryGap{}, Limitations: []string{
		"path-based-expectations-do-not-enumerate-all-components",
		"runtime-build-and-transitive-inventory-not-independently-proven",
		"sbom-quality-score-does-not-prove-inventory-coverage",
	}}
	for _, value := range lock.Detected.ExpectedEcosystems {
		if detect.KnownEcosystem(value) {
			r.ExpectedEcosystems = append(r.ExpectedEcosystems, value)
		} else {
			r.Gaps = append(r.Gaps, InventoryGap{Reason: "UNRECOGNIZED_INVENTORY_EXPECTATION"})
		}
	}
	r.ExpectedEcosystems = unique(r.ExpectedEcosystems)
	verified := false
	for _, c := range coverage {
		if c.Scanner == "syft" {
			verified = c.Complete && c.ParsingStatus == "PARSED"
			if verified {
				r.Evidence = append(r.Evidence, c.Evidence...)
			}
		}
	}
	observed := map[string]bool{}
	missingVersion := map[string]bool{}
	uncertainEcosystem := false
	if verified {
		for _, o := range observations {
			if o.Scanner != "syft" || o.Native.Category != "inventory" {
				continue
			}
			ecosystem, ambiguous := inventoryEcosystem(o.Native)
			uncertainEcosystem = uncertainEcosystem || ambiguous
			if ecosystem == "" {
				continue
			}
			observed[ecosystem] = true
			if strings.TrimSpace(o.Native.ComponentVersion) == "" {
				missingVersion[ecosystem] = true
			}
		}
	}
	for ecosystem := range observed {
		r.ObservedEcosystems = append(r.ObservedEcosystems, ecosystem)
	}
	r.ObservedEcosystems = unique(r.ObservedEcosystems)
	if uncertainEcosystem {
		r.Gaps = append(r.Gaps, InventoryGap{Reason: "INVENTORY_ECOSYSTEM_AMBIGUOUS"})
	}
	for _, input := range lock.Detected.DependencyInputs {
		if !detect.KnownEcosystem(input.Ecosystem) || !knownInputFormat(input.Format) || (input.Scope != "unspecified" && input.Scope != "build") || (input.Support != detect.RecognizedFormat && input.Support != detect.UnsupportedFormat) {
			r.Gaps = append(r.Gaps, InventoryGap{Reason: "UNRECOGNIZED_INVENTORY_EXPECTATION"})
			continue
		}
		if input.Support == detect.UnsupportedFormat {
			r.Gaps = append(r.Gaps, InventoryGap{Ecosystem: input.Ecosystem, Format: input.Format, Scope: input.Scope, Reason: "UNSUPPORTED_INPUT_FORMAT"})
		}
	}
	// Old reports/locks did not record dependency expectations. Never backfill a
	// positive adequacy claim from their old execution-only coverage flag.
	if len(lock.Detected.ExpectedEcosystems) == 0 && len(lock.Detected.Languages) > 0 {
		r.Gaps = append(r.Gaps, InventoryGap{Reason: "INVENTORY_EXPECTATIONS_NOT_RECORDED"})
	}
	for _, ecosystem := range r.ExpectedEcosystems {
		if !verified {
			r.Gaps = append(r.Gaps, InventoryGap{Ecosystem: ecosystem, Reason: "INVENTORY_EVIDENCE_UNAVAILABLE"})
		} else if !observed[ecosystem] {
			// A manifest can have no dependencies. Without content-level proof,
			// empty inventory is unresolved, rather than a fabricated clean pass.
			r.Gaps = append(r.Gaps, InventoryGap{Ecosystem: ecosystem, Reason: "EXPECTED_ECOSYSTEM_NOT_OBSERVED"})
		} else if missingVersion[ecosystem] {
			r.Gaps = append(r.Gaps, InventoryGap{Ecosystem: ecosystem, Reason: "INVENTORY_VERSION_MISSING"})
		}
	}
	sort.Slice(r.Gaps, func(i, j int) bool {
		a, b := r.Gaps[i], r.Gaps[j]
		return a.Ecosystem+"\x00"+a.Format+"\x00"+a.Scope+"\x00"+a.Reason < b.Ecosystem+"\x00"+b.Format+"\x00"+b.Scope+"\x00"+b.Reason
	})
	deduplicated := make([]InventoryGap, 0, len(r.Gaps))
	for _, gap := range r.Gaps {
		if len(deduplicated) == 0 || deduplicated[len(deduplicated)-1] != gap {
			deduplicated = append(deduplicated, gap)
		}
	}
	r.Gaps = deduplicated
	r.Adequate = len(r.Gaps) == 0
	if r.Adequate {
		r.Status = "ADEQUATE_FOR_DETECTED_ECOSYSTEMS"
		if len(r.ExpectedEcosystems) == 0 {
			r.Status = "NO_DETECTED_DEPENDENCY_INPUTS"
		}
	}
	return r
}

func inventoryEcosystem(item nativeItem) (string, bool) {
	purlValue, typeValue := "", ""
	purl := strings.ToLower(item.PURL)
	if strings.HasPrefix(purl, "pkg:") {
		kind, _, ok := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
		if ok {
			switch kind {
			case "golang":
				purlValue = "Go"
			case "pypi":
				purlValue = "PyPI"
			case "npm":
				purlValue = "npm"
			case "cargo":
				purlValue = "crates.io"
			case "github":
				if item.ComponentType == "github-action" {
					purlValue = "GitHubActions"
				}
			}
		}
	}
	switch item.ComponentType {
	case "go-module":
		typeValue = "Go"
	case "python":
		typeValue = "PyPI"
	case "npm":
		typeValue = "npm"
	case "rust-crate":
		typeValue = "crates.io"
	case "github-action":
		typeValue = "GitHubActions"
	}
	if purlValue != "" && typeValue != "" && purlValue != typeValue {
		return "", true
	}
	if purlValue != "" {
		return purlValue, false
	}
	return typeValue, false
}

func knownInputFormat(value string) bool {
	switch value {
	case "go.mod", "go.sum", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock", "requirements.lock", "build-requirements.lock", "cargo.toml", "cargo.lock":
		return true
	}
	return false
}

// Both outputs originate in the same admitted Syft execution, but hashes and
// lineage alone do not prove that the SBOM handed to Grype contains the native
// inventory. Compare private component identities without exporting any of them.
func consistentInventoryExport(native []nativeItem, data []byte) bool {
	value, err := decodeJSON(data)
	if err != nil {
		return false
	}
	document := obj(value)
	if str(document, "bomFormat") != "CycloneDX" {
		return false
	}
	components, ok := document["components"].([]any)
	if !ok || len(components) > maxItems {
		return false
	}
	key := func(name, version, purl string) string {
		return name + "\x00" + version + "\x00" + purl
	}
	expected := map[string]int{}
	for _, item := range native {
		if item.Category == "inventory" {
			expected[key(item.Component, item.ComponentVersion, item.PURL)]++
		}
	}
	pending := append([]any(nil), components...)
	visited := 0
	for len(pending) > 0 {
		value := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		visited++
		if visited > maxItems {
			return false
		}
		component := obj(value)
		if component == nil {
			return false
		}
		name, err := completenessText(component, "name")
		if err != nil || name == "" {
			return false
		}
		version, err := completenessText(component, "version")
		if err != nil {
			return false
		}
		purl, err := completenessText(component, "purl")
		if err != nil {
			return false
		}
		identity := key(name, version, purl)
		if expected[identity] > 0 {
			expected[identity]--
		} else if str(component, "type") != "file" || version != "" || purl != "" {
			// Syft's CycloneDX export can include unversioned source files
			// without package URLs which are absent from native artifacts.
			return false
		}
		if children, exists := component["components"]; exists {
			items, ok := children.([]any)
			if !ok || len(items)+visited+len(pending) > maxItems {
				return false
			}
			pending = append(pending, items...)
		}
	}
	for _, count := range expected {
		if count != 0 {
			return false
		}
	}
	return true
}
