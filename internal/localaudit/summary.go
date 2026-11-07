package localaudit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

const RunSummaryVersion = "pao.dev/run-summary/v1"
const ConfirmationVersion = "pao.dev/run-confirmation/v1"

// Confirmation records only the exact operator-approved identity. It grants
// no authority to a later run and is never accepted as reusable approval.
type Confirmation struct {
	Version      string    `json:"version"`
	AuditID      string    `json:"audit_id"`
	PlanDigest   string    `json:"plan_digest"`
	ConfigDigest string    `json:"configuration_digest"`
	TargetID     string    `json:"target_id"`
	ConfirmedAt  time.Time `json:"confirmed_at"`
}

// RunSummary is private local metadata. It deliberately keeps execution,
// evidence interpretation and human review as separate dimensions. Absolute
// paths belong here, never in a portable report or public release evidence.
type RunSummary struct {
	Version                  string              `json:"version"`
	AuditID                  string              `json:"audit_id"`
	Profile                  string              `json:"profile"`
	PlanDigest               string              `json:"plan_digest"`
	ConfigurationDigest      string              `json:"configuration_digest"`
	TargetID                 string              `json:"target_id"`
	Producer                 *buildinfo.Producer `json:"producer,omitempty"`
	ProducerStatus           string              `json:"producer_status"`
	ExecutionStatus          string              `json:"execution_status"`
	ReviewStatus             string              `json:"review_status"`
	ResultStatus             string              `json:"result_status"`
	ReportStatus             string              `json:"report_status"`
	CoverageComplete         bool                `json:"coverage_complete"`
	AnalysisCoverageComplete bool                `json:"analysis_coverage_complete"`
	InventoryCoverageStatus  string              `json:"inventory_coverage_status"`
	ExitCode                 int                 `json:"exit_code"`
	EvidenceDirectory        string              `json:"evidence_directory"`
	ReportDirectory          string              `json:"report_directory"`
	ReasonCodes              []string            `json:"reason_codes"`
}

func newRunSummary(id, profile string, prepared preparedAudit, evidence, reports string) RunSummary {
	s := RunSummary{
		Version: RunSummaryVersion, AuditID: id, Profile: profile,
		PlanDigest: prepared.plan.PlanDigest, ConfigurationDigest: prepared.configDigest,
		TargetID: prepared.snapshot.TargetID, ProducerStatus: "UNAVAILABLE",
		ExecutionStatus: "FAILED", ReviewStatus: "REVIEW_REQUIRED", ResultStatus: "UNAVAILABLE",
		ReportStatus: "UNAVAILABLE", InventoryCoverageStatus: "UNAVAILABLE",
		EvidenceDirectory: evidence, ReportDirectory: reports,
		ReasonCodes: []string{"RUN_NOT_STARTED"},
	}
	if producer, err := buildinfo.Current(); err == nil && producer.Validate() == nil {
		s.Producer, s.ProducerStatus = &producer, "RECORDED"
	}
	return s
}

func (s *RunSummary) finish(ctx context.Context, lock plan.Plan, record runner.Record, result auditresult.Result, runErr, reportErr error) {
	s.ExecutionStatus = classifyExecution(ctx, lock, record, runErr)
	s.ReasonCodes = []string{}
	if runErr != nil {
		s.ReasonCodes = append(s.ReasonCodes, "RUN_INCOMPLETE")
	}
	if ctx.Err() != nil {
		s.ReasonCodes = append(s.ReasonCodes, "RUN_CANCELLED")
	}
	if result.Version == auditresult.Version {
		s.ResultStatus = result.Status
		s.CoverageComplete, s.AnalysisCoverageComplete = result.CoverageComplete, result.AnalysisCoverageComplete
		if result.InventoryCoverage.Status != "" {
			s.InventoryCoverageStatus = result.InventoryCoverage.Status
		}
	}
	if reportErr == nil {
		s.ReportStatus = "GENERATED"
	} else {
		s.ReportStatus = "FAILED"
		s.ReasonCodes = append(s.ReasonCodes, "REPORT_WRITE_FAILED")
	}
	// Reasons are host-owned bounded codes, never scanner text or error strings.
	if s.ExecutionStatus == "POLICY_BLOCKED" {
		s.ReasonCodes = append(s.ReasonCodes, "EXECUTION_POLICY_BLOCKED")
	} else if s.ExecutionStatus == "FAILED" {
		s.ReasonCodes = append(s.ReasonCodes, "EXECUTION_FAILED")
	} else if s.ExecutionStatus == "INCOMPLETE" && runErr == nil {
		s.ReasonCodes = append(s.ReasonCodes, "EXECUTION_INCOMPLETE")
	}
	sort.Strings(s.ReasonCodes)
}

func classifyExecution(ctx context.Context, lock plan.Plan, record runner.Record, runErr error) string {
	if ctx.Err() != nil {
		return "CANCELLED"
	}
	if runErr != nil {
		if len(record.Executions) == 0 {
			return "FAILED"
		}
		return "INCOMPLETE"
	}
	if record.Validate() != nil || record.PlanDigest != lock.PlanDigest {
		return "INCOMPLETE"
	}
	nodes := make(map[string]plan.AdapterNode, len(lock.Nodes))
	for _, node := range lock.Nodes {
		nodes[node.ID] = node
	}
	seen := make(map[string]bool, len(record.Executions))
	blocked, failed, incomplete := false, false, false
	for _, execution := range record.Executions {
		node, found := nodes[execution.AdapterID]
		if !found || seen[execution.AdapterID] {
			incomplete = true
		}
		seen[execution.AdapterID] = true
		if found && node.Status == toolchain.ReasonNotApplicable && execution.Status == runner.Unsupported && execution.Coverage.ReasonCode == toolchain.ReasonNotApplicable {
			continue
		}
		switch execution.Status {
		case runner.Succeeded, runner.NoFindings:
		case runner.PolicyBlocked:
			blocked = true
		case runner.Failed:
			failed = true
		default:
			incomplete = true
		}
	}
	if blocked {
		return "POLICY_BLOCKED"
	}
	if failed {
		return "FAILED"
	}
	if incomplete || len(seen) != len(nodes) {
		return "INCOMPLETE"
	}
	return "COMPLETED"
}

func writeRunSummary(evidence string, summary RunSummary) error {
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return writeOnce(filepath.Join(evidence, "run-summary.json"), append(raw, '\n'), 0o600)
}
