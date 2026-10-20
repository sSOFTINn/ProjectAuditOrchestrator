package auditresult

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/adapters/sbomqs"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/license"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

const Version = "pao.dev/unified-report/v1"
const ParserVersion = "pao-native-projection/6"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Coverage struct {
	Scanner              string   `json:"scanner"`
	ExecutionStatus      string   `json:"execution_status"`
	ParsingStatus        string   `json:"parsing_status"`
	Reasons              []string `json:"reason_codes,omitempty"`
	Evidence             []string `json:"evidence_refs,omitempty"`
	Observations         int      `json:"observations"`
	Complete             bool     `json:"complete"`
	DiagnosticCode       string   `json:"diagnostic_code,omitempty"`
	DiagnosticsAvailable bool     `json:"diagnostics_available,omitempty"`
	Applicability        string   `json:"applicability"`
	SupportStatus        string   `json:"support_status"`
	SupportReasons       []string `json:"support_reason_codes,omitempty"`
	Limitations          []string `json:"limitations,omitempty"`
}

// Observation lives in the private evidence directory. Native strings are data,
// and are never copied into the portable result or interpreted as Markdown.
type Observation struct {
	ID                string     `json:"id"`
	Scanner           string     `json:"scanner"`
	ScannerVersion    string     `json:"scanner_version"`
	ExecutionID       string     `json:"execution_id"`
	Evidence          string     `json:"raw_result_ref"`
	ConfigDigest      string     `json:"config_digest"`
	DatabaseDigest    string     `json:"database_digest,omitempty"`
	RulePackDigest    string     `json:"rule_pack_digest,omitempty"`
	LicenseDataDigest string     `json:"license_data_digest,omitempty"`
	ToolDigest        string     `json:"tool_digest"`
	Native            nativeItem `json:"scanner_observation"`
}

// SBOMQualityObservation is private, bounded evidence that a local quality tool
// assessed one captured CycloneDX document. The score is informational only.
type SBOMQualityObservation struct {
	ID              string  `json:"id"`
	ScannerVersion  string  `json:"scanner_version"`
	ExecutionID     string  `json:"execution_id"`
	SBOMEvidence    string  `json:"sbom_evidence_ref"`
	ResultEvidence  string  `json:"raw_result_ref"`
	ConfigDigest    string  `json:"config_digest"`
	ToolDigest      string  `json:"tool_digest"`
	Score           float64 `json:"score"`
	MissingName     int     `json:"missing_component_name"`
	MissingVersion  int     `json:"missing_component_version"`
	MissingLicense  int     `json:"missing_component_license"`
	MissingSupplier int     `json:"missing_component_supplier"`
}

func (o SBOMQualityObservation) MissingCategories() []string {
	values := make([]string, 0, 4)
	if o.MissingName > 0 {
		values = append(values, "component-name")
	}
	if o.MissingVersion > 0 {
		values = append(values, "component-version")
	}
	if o.MissingLicense > 0 {
		values = append(values, "component-license")
	}
	if o.MissingSupplier > 0 {
		values = append(values, "component-supplier")
	}
	return values
}

type Result struct {
	RunProducer          *buildinfo.Producer `json:"run_producer,omitempty"`
	RunProducerStatus    string              `json:"run_producer_status"`
	ReportProducer       *buildinfo.Producer `json:"report_producer,omitempty"`
	ReportProducerStatus string              `json:"report_producer_status"`
	Version              string              `json:"version"`
	ParserVersion        string              `json:"parser_version"`
	PlanDigest           string              `json:"plan_digest"`
	TargetID             string              `json:"target_id"`
	Status               string              `json:"status"`
	CoverageComplete     bool                `json:"coverage_complete"`
	// CoverageComplete retains its execution/parsing meaning. Analysis coverage
	// additionally includes known input/feed support and inventory adequacy.
	AnalysisCoverageComplete bool                     `json:"analysis_coverage_complete"`
	InventoryCoverage        InventoryCoverage        `json:"inventory_coverage"`
	Reasons                  []string                 `json:"reason_codes,omitempty"`
	Coverage                 []Coverage               `json:"coverage"`
	Observations             []Observation            `json:"observations"`
	SBOMQuality              []SBOMQualityObservation `json:"sbom_quality_observations,omitempty"`
	Findings                 []normalize.Finding      `json:"findings"`
	LicenseReview            []license.ReviewItem     `json:"license_review"`
}

func knownScanner(id string) bool {
	switch id {
	case "syft", "sbomqs", "grype", "osv-scanner", "trivy", "gitleaks", "opengrep", "zizmor", "scancode", "reuse":
		return true
	}
	return false
}

// Build performs no writes, launches no processes and does not read the target.
// plan is the in-memory confirmed plan, not a scanner-owned declaration.
func Build(root string, lock plan.Plan, record runner.Record, catalog *toolchain.Registry, runFailed bool) Result {
	r := Result{Version: Version, ParserVersion: ParserVersion, PlanDigest: lock.PlanDigest, TargetID: lock.TargetID, Status: "REVIEW_REQUIRED", CoverageComplete: true, Coverage: []Coverage{}, Observations: []Observation{}, SBOMQuality: []SBOMQualityObservation{}, Findings: []normalize.Finding{}, LicenseReview: []license.ReviewItem{}}
	r.RunProducerStatus = "UNKNOWN_HISTORICAL"
	if record.Producer != nil {
		if record.Producer.Validate() == nil {
			copy := *record.Producer
			r.RunProducer, r.RunProducerStatus = &copy, "RECORDED"
		} else {
			r.RunProducerStatus = "INVALID"
		}
	}
	r.ReportProducerStatus = "UNAVAILABLE"
	if producer, err := buildinfo.Current(); err == nil && producer.Validate() == nil {
		r.ReportProducer, r.ReportProducerStatus = &producer, "RECORDED"
	}
	if plan.Verify(lock) != nil || !digestPattern.MatchString(lock.TargetID) || len(lock.Nodes) == 0 || len(lock.Nodes) > 10 {
		r.Status = "INCOMPLETE"
		r.CoverageComplete = false
		r.Reasons = []string{"INVALID_PLAN"}
		r.PlanDigest = ""
		r.TargetID = ""
		return r
	}
	if runFailed {
		r.Reasons = append(r.Reasons, "RUN_INCOMPLETE")
	}
	if record.Validate() != nil || record.PlanDigest != lock.PlanDigest || record.TargetBefore.TargetID != lock.TargetID || !record.TargetBefore.Complete || !record.TargetAfter.Complete {
		r.Reasons = append(r.Reasons, "INVALID_RUN_RECORD")
	}
	byID := map[string][]runner.ToolExecution{}
	executionIDs := map[string]int{}
	rawClaims := map[string]int{}
	verifiedSBOMs := map[string]artifact.RawArtifact{}
	inventoryExportConsistent := true
	goModuleFileCatalogerUsed := false
	for _, e := range record.Executions {
		byID[e.AdapterID] = append(byID[e.AdapterID], e)
		executionIDs[e.ID]++
		for _, raw := range e.RawArtifacts {
			rawClaims[raw.SHA256]++
		}
	}
	nodes := append([]plan.AdapterNode(nil), lock.Nodes...)
	// Validate producers before their consumers, regardless of record ordering.
	sort.Slice(nodes, func(i, j int) bool {
		if (nodes[i].ID == "sbomqs") != (nodes[j].ID == "sbomqs") {
			return nodes[j].ID == "sbomqs"
		}
		return nodes[i].ID < nodes[j].ID
	})
	seen := map[string]bool{}
	budget := 16 << 20
	for _, n := range nodes {
		if !knownScanner(n.ID) || seen[n.ID] {
			r.Reasons = append(r.Reasons, "INVALID_PLAN_NODE")
			continue
		}
		seen[n.ID] = true
		c := nodeCoverage(n)
		outcomes := byID[n.ID]
		delete(byID, n.ID)
		if len(outcomes) != 1 {
			c.Reasons = []string{"MISSING_OR_DUPLICATE_EXECUTION"}
			r.Coverage = append(r.Coverage, c)
			continue
		}
		e := outcomes[0]
		c.ExecutionStatus = e.Status
		if e.Validate() != nil || executionIDs[e.ID] != 1 || e.PlanDigest != lock.PlanDigest || e.ConfigDigest != n.ConfigDigest || e.ManifestDigest != n.ManifestDigest || e.ToolID != n.ID || e.Coverage.Capability != n.Capability {
			c.ExecutionStatus = "INVALID"
			c.Reasons = []string{"INVALID_EXECUTION_LINEAGE"}
			r.Coverage = append(r.Coverage, c)
			continue
		}
		if e.Coverage.Validate() != nil {
			c.Reasons = append(c.Reasons, "INVALID_COVERAGE_REASON")
		} else if e.Coverage.ReasonCode != "" {
			c.Reasons = append(c.Reasons, e.Coverage.ReasonCode)
		}
		// Diagnostics are verified independently, never sent into native result parsers.
		// Only a closed-set code and availability flag reach the portable projection.
		if runner.KnownDiagnosticCode(e.DiagnosticCode) {
			c.DiagnosticCode = e.DiagnosticCode
		}
		for _, d := range e.Diagnostics {
			if _, err := readRaw(root, d.Artifact, e.ID); err != nil {
				c.Reasons = append(c.Reasons, "EVIDENCE_INTEGRITY_FAILURE")
			} else {
				c.DiagnosticsAvailable = true
			}
			if d.Truncated {
				c.Reasons = append(c.Reasons, "CAPTURE_TRUNCATED")
			}
		}
		if e.StdoutTruncated {
			c.Reasons = append(c.Reasons, "CAPTURE_TRUNCATED")
		}
		if n.Status == toolchain.ReasonNotApplicable && e.Status == runner.Unsupported && e.Coverage.ReasonCode == toolchain.ReasonNotApplicable && len(e.RawArtifacts) == 0 {
			c.ParsingStatus = "NOT_APPLICABLE"
			c.Complete = true
			r.Coverage = append(r.Coverage, c)
			continue
		}
		if e.Status == runner.Unavailable || e.Status == runner.PolicyBlocked || e.Status == runner.Unsupported {
			c.ParsingStatus = "NOT_AVAILABLE"
			if e.Status == runner.Unsupported && n.Applicability == "APPLICABLE" && n.SupportStatus == "UNSUPPORTED" {
				c.ParsingStatus = "UNSUPPORTED_INPUT"
			}
			r.Coverage = append(r.Coverage, c)
			continue
		}
		if e.Coverage.ReasonCode == toolchain.ReasonNotApplicable {
			c.Reasons = append(c.Reasons, "UNCONFIRMED_SKIP")
		}
		if n.Status == toolchain.ReasonNotApplicable {
			c.Reasons = append(c.Reasons, "UNCONFIRMED_SKIP")
		}
		if n.ID == "sbomqs" {
			if !e.Coverage.Complete() || len(c.Reasons) != 0 || len(r.Reasons) != 0 {
				c.Reasons = append(c.Reasons, "SBOM_QUALITY_INCOMPLETE")
				r.Coverage = append(r.Coverage, c)
				continue
			}
			quality, qualityCoverage := parseSBOMQuality(root, e, catalog, verifiedSBOMs)
			qualityCoverage.Scanner, qualityCoverage.ExecutionStatus = n.ID, e.Status
			qualityCoverage.Reasons = append(qualityCoverage.Reasons, c.Reasons...)
			qualityCoverage.DiagnosticCode, qualityCoverage.DiagnosticsAvailable = c.DiagnosticCode, c.DiagnosticsAvailable
			qualityCoverage.Applicability, qualityCoverage.SupportStatus = c.Applicability, c.SupportStatus
			qualityCoverage.SupportReasons, qualityCoverage.Limitations = c.SupportReasons, c.Limitations
			qualityCoverage.Reasons = unique(qualityCoverage.Reasons)
			if quality != nil {
				r.SBOMQuality = append(r.SBOMQuality, *quality)
			}
			r.Coverage = append(r.Coverage, qualityCoverage)
			continue
		}
		if len(e.RawArtifacts) != 1 && !(n.ID == "syft" && len(e.RawArtifacts) == 2) {
			c.Reasons = append(c.Reasons, "MISSING_OR_AMBIGUOUS_RAW_RESULT")
			r.Coverage = append(r.Coverage, c)
			continue
		}
		raw := e.RawArtifacts[0]
		var capturedSBOM []byte
		var capturedErr error
		if n.ID == "syft" {
			native, cycloneDX := selectSyftArtifacts(e.RawArtifacts)
			if native == nil || cycloneDX == nil {
				c.Reasons = append(c.Reasons, "MISSING_OR_AMBIGUOUS_RAW_RESULT")
				r.Coverage = append(r.Coverage, c)
				continue
			}
			raw = *native
			capturedSBOM, capturedErr = readRaw(root, *cycloneDX, e.ID)
			if capturedErr != nil {
				c.ParsingStatus = "EVIDENCE_REJECTED"
				c.Reasons = append(c.Reasons, "EVIDENCE_INTEGRITY_FAILURE")
				r.Coverage = append(r.Coverage, c)
				continue
			}
			c.Evidence = append(c.Evidence, cycloneDX.SHA256)
		}
		data, err := readRaw(root, raw, e.ID)
		if err != nil {
			c.ParsingStatus = "EVIDENCE_REJECTED"
			c.Reasons = append(c.Reasons, "EVIDENCE_INTEGRITY_FAILURE")
			r.Coverage = append(r.Coverage, c)
			continue
		}
		c.Evidence = append([]string{raw.SHA256}, c.Evidence...)
		// The existing Docker host labels stdout as octet-stream. Only these two
		// fixed JSON stdout commands may enter the same strict native decoder.
		stdoutJSON := (n.ID == "reuse" || n.ID == "zizmor") && raw.MediaType == "application/octet-stream"
		if raw.MediaType != "application/json" && !(n.ID == "syft" && raw.MediaType == "application/vnd.syft+json") && !stdoutJSON {
			c.ParsingStatus = "UNSUPPORTED_FORMAT"
			c.Reasons = append(c.Reasons, "UNSUPPORTED_MEDIA_TYPE")
			r.Coverage = append(r.Coverage, c)
			continue
		}
		version, err := catalog.VersionForDigest(e.ToolID, e.ToolDigest)
		if err != nil {
			c.ParsingStatus = "EVIDENCE_REJECTED"
			c.Reasons = append(c.Reasons, "UNKNOWN_TOOL_IDENTITY")
			r.Coverage = append(r.Coverage, c)
			continue
		}
		p := parseNative(n.ID, data)
		if n.ID == "syft" && p.Status == "PARSED" {
			goModuleFileCatalogerUsed = p.GoModuleFileCatalogerUsed
		}
		if n.ID == "syft" && p.Status == "PARSED" && !consistentInventoryExport(p.Items, capturedSBOM) {
			inventoryExportConsistent = false
		}
		c.ParsingStatus = p.Status
		c.Reasons = append(c.Reasons, p.Reasons...)
		for index, item := range p.Items {
			if item.Category == "license" && strings.ContainsAny(item.Expression, " ()\t\r\n") && item.ReviewReason == "" {
				item.ReviewReason = "COMPOUND_LICENSE_REVIEW"
			}
			cost := 0
			for _, v := range item.textValues() {
				cost += len(v)
			}
			if len(r.Observations) >= maxItems || cost > budget {
				c.ParsingStatus = "PARTIAL"
				c.Reasons = append(c.Reasons, "RESULT_LIMIT")
				break
			}
			budget -= cost
			id := "observation-" + normalize.Fingerprint(e.ID, raw.SHA256, strconv.Itoa(index))
			o := Observation{ID: id, Scanner: n.ID, ScannerVersion: version, ExecutionID: e.ID, Evidence: raw.SHA256, ConfigDigest: e.ConfigDigest, DatabaseDigest: e.DatabaseDigest, RulePackDigest: e.RulePackDigest, LicenseDataDigest: e.LicenseDataDigest, ToolDigest: e.ToolDigest, Native: item}
			r.Observations = append(r.Observations, o)
			c.Observations++
			if item.Category == "inventory" {
				continue
			}
			if item.Category == "license" && item.Expression != "" {
				q, err := license.Queue([]license.Observation{{ComponentID: id, SPDXExpression: item.Expression, EvidenceRefs: []string{raw.SHA256}, Status: license.StatusObserved}})
				if err != nil {
					c.ParsingStatus = "PARTIAL"
					c.Reasons = append(c.Reasons, "INVALID_LICENSE_OBSERVATION")
				} else {
					r.LicenseReview = append(r.LicenseReview, q...)
					if len(q) == 0 && item.ReviewReason == "" {
						continue
					}
				}
			}
			f := canonical(o, lock.TargetID)
			if err := f.Validate(); err != nil {
				c.ParsingStatus = "PARTIAL"
				c.Reasons = append(c.Reasons, "INVALID_CANONICAL_FINDING")
				continue
			}
			r.Findings = append(r.Findings, f)
		}
		if e.Status == runner.NoFindings && len(r.Findings) > 0 && c.Observations > 0 { // Check only this execution, not preceding adapters.
			for _, f := range r.Findings {
				if f.ToolExecutionID == e.ID {
					c.Reasons = append(c.Reasons, "CONTRADICTORY_RESULT")
					c.ParsingStatus = "PARTIAL"
					break
				}
			}
		}
		c.Complete = e.Coverage.Complete() && c.ParsingStatus == "PARSED" && len(c.Reasons) == 0
		if n.ID == "syft" && c.Complete {
			_, cycloneDX := selectSyftArtifacts(e.RawArtifacts)
			if cycloneDX != nil && rawClaims[cycloneDX.SHA256] == 1 {
				verifiedSBOMs[cycloneDX.SHA256] = *cycloneDX
			}
		}
		r.Coverage = append(r.Coverage, c)
	}
	if len(byID) > 0 {
		r.Reasons = append(r.Reasons, "UNEXPECTED_EXECUTION")
	}
	if len(r.Reasons) > 0 {
		r.CoverageComplete = false
		r.SBOMQuality = nil
		for i := range r.Coverage {
			if r.Coverage[i].Scanner == "sbomqs" {
				r.Coverage[i].Complete = false
				r.Coverage[i].Reasons = append(r.Coverage[i].Reasons, "SBOM_QUALITY_INCOMPLETE")
			}
		}
	}
	blocked := false
	for i := range r.Coverage {
		c := &r.Coverage[i]
		c.Reasons = unique(c.Reasons)
		if !c.Complete {
			r.CoverageComplete = false
		}
		if c.ExecutionStatus == runner.PolicyBlocked {
			blocked = true
		}
	}
	if !r.CoverageComplete {
		r.Status = "INCOMPLETE"
	}
	goEmptyVerified := inventoryExportConsistent && goModuleFileCatalogerUsed && record.Validate() == nil && record.PlanDigest == lock.PlanDigest &&
		record.TargetBefore.TargetID == lock.TargetID && record.TargetAfter.TargetID == lock.TargetID &&
		sameGoDeclarationEvidence(lock.Detected.EmptyGoModuleHashes, record.TargetBefore, record.TargetAfter)
	r.InventoryCoverage = assessInventory(lock, r.Coverage, r.Observations, goEmptyVerified)
	if !inventoryExportConsistent {
		r.InventoryCoverage.Gaps = append(r.InventoryCoverage.Gaps, InventoryGap{Reason: "SBOM_EXPORT_INVENTORY_MISMATCH"})
		r.InventoryCoverage.Adequate, r.InventoryCoverage.Status = false, "PARTIAL"
	}
	r.AnalysisCoverageComplete = r.CoverageComplete && r.InventoryCoverage.Adequate
	for _, c := range r.Coverage {
		if c.SupportStatus == "PARTIAL" || c.SupportStatus == "UNSUPPORTED" || c.SupportStatus == "NOT_RECORDED" || len(c.SupportReasons) > 0 {
			r.AnalysisCoverageComplete = false
		}
		for _, limitation := range c.Limitations {
			if limitation == "unrecognized-manifest-limitation" {
				r.AnalysisCoverageComplete = false
			}
		}
	}
	if !r.AnalysisCoverageComplete {
		r.Status = "INCOMPLETE"
	}
	if blocked {
		r.Status = "POLICY_BLOCKED"
	}
	r.Reasons = unique(r.Reasons)
	sort.Slice(r.Coverage, func(i, j int) bool { return r.Coverage[i].Scanner < r.Coverage[j].Scanner })
	sort.Slice(r.Observations, func(i, j int) bool { return r.Observations[i].ID < r.Observations[j].ID })
	sort.Slice(r.SBOMQuality, func(i, j int) bool { return r.SBOMQuality[i].ID < r.SBOMQuality[j].ID })
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].FindingID < r.Findings[j].FindingID })
	sort.Slice(r.LicenseReview, func(i, j int) bool { return r.LicenseReview[i].ComponentID < r.LicenseReview[j].ComponentID })
	return r
}

func sameGoDeclarationEvidence(hashes []string, before, after target.Snapshot) bool {
	if len(hashes) == 0 || len(hashes) > 1000 {
		return false
	}
	// Compare exact canonical sets. Duplicated, fabricated or historical
	// declarations cannot be upgraded by replaying a new report parser.
	expected := append([]string(nil), hashes...)
	sort.Strings(expected)
	return strings.Join(expected, "\n") == strings.Join(target.EmptyGoModuleHashes(before), "\n") &&
		strings.Join(expected, "\n") == strings.Join(target.EmptyGoModuleHashes(after), "\n")
}

func selectSyftArtifacts(artifacts []artifact.RawArtifact) (*artifact.RawArtifact, *artifact.RawArtifact) {
	if len(artifacts) != 2 {
		return nil, nil
	}
	var native, cycloneDX *artifact.RawArtifact
	for index := range artifacts {
		switch artifacts[index].MediaType {
		case "application/vnd.syft+json":
			if native != nil {
				return nil, nil
			}
			native = &artifacts[index]
		case "application/vnd.cyclonedx+json":
			if cycloneDX != nil {
				return nil, nil
			}
			cycloneDX = &artifacts[index]
		default:
			return nil, nil
		}
	}
	return native, cycloneDX
}

func parseSBOMQuality(root string, e runner.ToolExecution, catalog *toolchain.Registry, verifiedSBOMs map[string]artifact.RawArtifact) (*SBOMQualityObservation, Coverage) {
	c := Coverage{Scanner: "sbomqs", ExecutionStatus: e.Status, ParsingStatus: "NOT_AVAILABLE"}
	if len(e.RawArtifacts) != 1 || e.InputArtifact == nil {
		c.Reasons = []string{"MISSING_OR_AMBIGUOUS_RAW_RESULT"}
		return nil, c
	}
	input := *e.InputArtifact
	producer, found := verifiedSBOMs[input.SHA256]
	if input.MediaType != "application/vnd.cyclonedx+json" || !found || input != producer {
		c.Reasons = []string{"INVALID_SBOM_LINEAGE"}
		return nil, c
	}
	inputData, err := readRaw(root, input, "")
	if err != nil {
		c.Reasons = []string{"EVIDENCE_INTEGRITY_FAILURE"}
		return nil, c
	}
	completeness, err := inspectCycloneDX(inputData)
	if err != nil {
		c.ParsingStatus, c.Reasons = "UNSUPPORTED", []string{"INVALID_SBOM_FORMAT"}
		return nil, c
	}
	raw := e.RawArtifacts[0]
	if raw.MediaType != "application/octet-stream" && raw.MediaType != "application/json" {
		c.Reasons = []string{"UNSUPPORTED_MEDIA_TYPE"}
		return nil, c
	}
	data, err := readRaw(root, raw, e.ID)
	if err != nil {
		c.ParsingStatus, c.Reasons = "EVIDENCE_REJECTED", []string{"EVIDENCE_INTEGRITY_FAILURE"}
		return nil, c
	}
	version, err := catalog.VersionForDigest(e.ToolID, e.ToolDigest)
	if err != nil {
		c.ParsingStatus, c.Reasons = "EVIDENCE_REJECTED", []string{"UNKNOWN_TOOL_IDENTITY"}
		return nil, c
	}
	parsed := sbomqs.Parse(data)
	if parsed.Status != "SUCCEEDED" {
		c.ParsingStatus, c.Reasons = parsed.Status, []string{"SBOMQS_OUTPUT_INVALID"}
		return nil, c
	}
	c.ParsingStatus, c.Evidence, c.Observations = "PARSED", []string{input.SHA256, raw.SHA256}, 1+completeness.totalMissing()
	c.Complete = e.Coverage.Complete()
	return &SBOMQualityObservation{ID: "sbom-quality-" + normalize.Fingerprint(input.SHA256, raw.SHA256, e.ConfigDigest, e.ToolDigest), ScannerVersion: version, ExecutionID: e.ID, SBOMEvidence: input.SHA256, ResultEvidence: raw.SHA256, ConfigDigest: e.ConfigDigest, ToolDigest: e.ToolDigest, Score: parsed.Score, MissingName: completeness.name, MissingVersion: completeness.version, MissingLicense: completeness.license, MissingSupplier: completeness.supplier}, c
}

type cyclonedxCompleteness struct {
	name     int
	version  int
	license  int
	supplier int
}

func (c cyclonedxCompleteness) totalMissing() int {
	return c.name + c.version + c.license + c.supplier
}

// inspectCycloneDX reads only the whitelisted component-presence indicators from
// protected evidence. It intentionally never transfers component names or paths to
// portable reports.
func inspectCycloneDX(raw []byte) (cyclonedxCompleteness, error) {
	value, err := decodeJSON(raw)
	if err != nil {
		return cyclonedxCompleteness{}, err
	}
	document := obj(value)
	if document == nil || str(document, "bomFormat") != "CycloneDX" || str(document, "specVersion") == "" {
		return cyclonedxCompleteness{}, errors.New("unsupported CycloneDX document")
	}
	componentsValue, exists := document["components"]
	if !exists {
		// The components field is optional. Inventory consistency is checked
		// separately against native Syft before any adequacy decision.
		return cyclonedxCompleteness{}, nil
	}
	components, found := componentsValue.([]any)
	if !found {
		return cyclonedxCompleteness{}, errors.New("invalid CycloneDX components")
	}
	if len(components) > maxItems {
		return cyclonedxCompleteness{}, errors.New("CycloneDX component limit")
	}
	var result cyclonedxCompleteness
	// Walk nested component lists too. The strict decoder already bounds depth;
	// this independent count bounds the total completeness workload.
	pending := append([]any(nil), components...)
	visited := 0
	for len(pending) > 0 {
		value := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		visited++
		if visited > maxItems {
			return cyclonedxCompleteness{}, errors.New("CycloneDX component limit")
		}
		component := obj(value)
		if component == nil {
			return cyclonedxCompleteness{}, errors.New("invalid CycloneDX component")
		}
		name, err := completenessText(component, "name")
		if err != nil {
			return cyclonedxCompleteness{}, err
		}
		version, err := completenessText(component, "version")
		if err != nil {
			return cyclonedxCompleteness{}, err
		}
		if name == "" {
			result.name++
		}
		if version == "" {
			result.version++
		}
		hasLicense, err := completenessLicense(component)
		if err != nil {
			return cyclonedxCompleteness{}, err
		}
		if !hasLicense {
			result.license++
		}
		supplierName := ""
		if supplierValue, found := component["supplier"]; found {
			supplier := obj(supplierValue)
			if supplier == nil {
				return cyclonedxCompleteness{}, errors.New("invalid CycloneDX supplier")
			}
			supplierName, err = completenessText(supplier, "name")
			if err != nil {
				return cyclonedxCompleteness{}, err
			}
		}
		if supplierName == "" {
			result.supplier++
		}
		if children, found := component["components"]; found {
			items, ok := children.([]any)
			if !ok {
				return cyclonedxCompleteness{}, errors.New("invalid nested CycloneDX components")
			}
			if visited+len(pending)+len(items) > maxItems {
				return cyclonedxCompleteness{}, errors.New("CycloneDX component limit")
			}
			pending = append(pending, items...)
		}
	}
	return result, nil
}

// These helpers inspect presence and shape, not licence validity or permission.
// Missing fields enter the review counts; wrong JSON types reject the input.
func completenessText(object map[string]any, field string) (string, error) {
	value, found := object[field]
	if !found {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", errors.New("invalid CycloneDX text field")
	}
	return strings.TrimSpace(text), nil
}

func completenessLicense(component map[string]any) (bool, error) {
	value, found := component["licenses"]
	if !found {
		return false, nil
	}
	licenses, ok := value.([]any)
	if !ok {
		return false, errors.New("invalid CycloneDX licenses")
	}
	present := false
	for _, value := range licenses {
		entry := obj(value)
		if entry == nil {
			return false, errors.New("invalid CycloneDX license entry")
		}
		licenseValue, hasLicense := entry["license"]
		_, hasExpression := entry["expression"]
		if hasLicense == hasExpression {
			return false, errors.New("ambiguous or missing CycloneDX license choice")
		}
		if hasExpression {
			expression, err := completenessText(entry, "expression")
			if err != nil {
				return false, err
			}
			present = present || expression != ""
			continue
		}
		license := obj(licenseValue)
		if license == nil {
			return false, errors.New("invalid CycloneDX license object")
		}
		id, err := completenessText(license, "id")
		if err != nil {
			return false, err
		}
		name, err := completenessText(license, "name")
		if err != nil {
			return false, err
		}
		present = present || id != "" || name != ""
	}
	return present, nil
}

func unique(a []string) []string {
	sort.Strings(a)
	out := []string{}
	for _, s := range a {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func readRaw(root string, ref artifact.RawArtifact, executionID string) ([]byte, error) {
	if !digestPattern.MatchString(ref.SHA256) || (executionID != "" && ref.ExecutionID != executionID) || ref.ExecutionID == "" || ref.Size < 0 || ref.Size > maxRawBytes {
		return nil, fmt.Errorf("invalid reference")
	}
	if ref.Path != "raw/sha256/"+ref.SHA256[7:] {
		return nil, fmt.Errorf("invalid raw path")
	}
	path := filepath.Join(root, filepath.FromSlash(ref.Path))
	if err := auditconfig.CheckPath(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != ref.Size {
		return nil, fmt.Errorf("invalid raw file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRawBytes+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != ref.Size || "sha256:"+hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, fmt.Errorf("raw digest mismatch")
	}
	return data, nil
}

func canonical(o Observation, targetID string) normalize.Finding {
	i := o.Native
	// Fingerprints intentionally do not claim cross-scanner equivalence. No observation
	// is removed: alias resolution/package-instance equivalence needs a separate policy.
	fingerprint := normalize.Fingerprint(o.Scanner, i.Category, i.Rule, i.Component, i.ComponentVersion, i.PURL, i.Path, strconv.Itoa(i.Line), i.Expression)
	f := normalize.Finding{Version: normalize.SchemaVersion, FindingID: "finding-" + strings.TrimPrefix(o.ID, "observation-"), StableFingerprint: fingerprint, Category: i.Category, Title: categoryLabel(i.Category), Status: "MANUAL_REVIEW", Severity: i.Severity, Confidence: "LOW", ScannerID: o.Scanner, ScannerVersion: o.ScannerVersion, RuleID: i.Rule, DatabaseVersion: o.DatabaseDigest, TargetID: targetID, ConfigHash: o.ConfigDigest, EvidenceRefs: []string{o.Evidence}, RawResultRef: o.Evidence, ToolExecutionID: o.ExecutionID, AssumptionIDs: []string{"SCANNER_ASSERTION_NOT_INDEPENDENTLY_VALIDATED"}}
	if safeLocation(i.Path) {
		f.Locations = []normalize.Location{{URI: strings.ReplaceAll(i.Path, "\\", "/"), Line: i.Line}}
	} else {
		f.AssumptionIDs = append(f.AssumptionIDs, "LOCATION_PRIVATE_OR_UNAVAILABLE")
	}
	if f.Severity == "UNKNOWN" {
		f.AssumptionIDs = append(f.AssumptionIDs, "SEVERITY_NOT_MAPPED")
	}
	return f
}
func safeLocation(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") || strings.Contains(s, ":") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
