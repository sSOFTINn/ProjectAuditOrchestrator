package localaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func readRunSummary(t *testing.T, c auditconfig.Config) RunSummary {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*", "run-summary.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one private run summary, got %v %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var summary RunSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Version != RunSummaryVersion || summary.ReviewStatus != "REVIEW_REQUIRED" || summary.AuditID == "" || summary.PlanDigest == "" || summary.TargetID == "" || summary.ConfigurationDigest == "" {
		t.Fatalf("unbound summary or false approval: %#v", summary)
	}
	if summary.EvidenceDirectory != filepath.Dir(files[0]) || !strings.HasPrefix(summary.ReportDirectory, c.ReportBase+string(filepath.Separator)) {
		t.Fatal("summary paths do not belong to this private run")
	}
	return summary
}

func summaryExecutor(t *testing.T, status string, cancel context.CancelFunc, reportCollision bool) scannerExecutor {
	t.Helper()
	return func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, capability string) (runner.ToolExecution, error) {
		e := runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: status, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: capability, Status: status, Reason: "synthetic outcome"}}
		if status == runner.Succeeded {
			raw, err := h.Artifacts.PutRaw("application/json", []byte(`[]`), id)
			if err != nil {
				t.Fatal(err)
			}
			e.Sandbox, e.RawArtifacts = s.Sandbox, append(e.RawArtifacts, raw)
		}
		if reportCollision {
			if err := os.WriteFile(filepath.Join(h.Artifacts.Root(), "result.private.json"), []byte("KEEP_EXISTING_EVIDENCE"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if cancel != nil {
			cancel()
			return e, context.Canceled
		}
		return e, nil
	}
}

func TestRunSummarySeparatesCompletedExecutionFromCoverageAndReview(t *testing.T) {
	c, file, _ := portableSetup(t)
	var out, errs bytes.Buffer
	code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, summaryExecutor(t, runner.Succeeded, nil, false))
	if code != 4 {
		t.Fatalf("completed audit changed legacy exit contract: %d %s", code, errs.String())
	}
	summary := readRunSummary(t, c)
	if summary.ExecutionStatus != "COMPLETED" || summary.ExitCode != 4 || summary.ReportStatus != "GENERATED" || !summary.CoverageComplete || summary.AnalysisCoverageComplete || summary.ProducerStatus != "RECORDED" || summary.Producer == nil {
		t.Fatalf("completion concealed coverage gap or lost source identity: %#v", summary)
	}
	confirmationBytes, err := os.ReadFile(filepath.Join(summary.EvidenceDirectory, "confirmation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var confirmation Confirmation
	if err := json.Unmarshal(confirmationBytes, &confirmation); err != nil || confirmation.Version != ConfirmationVersion || confirmation.AuditID != summary.AuditID || confirmation.PlanDigest != summary.PlanDigest || confirmation.ConfigDigest != summary.ConfigurationDigest || confirmation.TargetID != summary.TargetID || confirmation.ConfirmedAt.IsZero() {
		t.Fatalf("confirmation does not bind this run: %#v %v", confirmation, err)
	}
	public, err := os.ReadFile(filepath.Join(summary.ReportDirectory, "06_report", "report.json"))
	if err != nil || bytes.Contains(public, []byte(c.InstallationState)) || bytes.Contains(public, []byte(summary.EvidenceDirectory)) || bytes.Contains(public, []byte("run-summary.json")) {
		t.Fatalf("private execution paths leaked into portable result: %v", err)
	}
}

func TestRunSummaryDistinguishesFailureIncompleteBlockedAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, status, execution string
		cancel                  bool
		wantExit                int
	}{
		{"failed", runner.Failed, "FAILED", false, 4},
		{"timeout", runner.TimedOut, "INCOMPLETE", false, 4},
		{"unavailable", runner.Unavailable, "INCOMPLETE", false, 4},
		{"blocked", runner.PolicyBlocked, "POLICY_BLOCKED", false, 5},
		{"cancelled", runner.Failed, "CANCELLED", true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, file, _ := portableSetup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var cancelRun context.CancelFunc
			if tc.cancel {
				cancelRun = cancel
			}
			var out, errs bytes.Buffer
			code := command(ctx, []string{"--config", file, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, summaryExecutor(t, tc.status, cancelRun, false))
			if code != tc.wantExit {
				t.Fatalf("exit=%d errors=%s", code, errs.String())
			}
			summary := readRunSummary(t, c)
			if summary.ExecutionStatus != tc.execution || summary.ExitCode != code || summary.CoverageComplete || summary.AnalysisCoverageComplete {
				t.Fatalf("failure presented as completed coverage: %#v", summary)
			}
		})
	}
}

func TestRunSummarySurvivesReportWriteFailureWithoutReplacingEvidence(t *testing.T) {
	c, file, _ := portableSetup(t)
	var out, errs bytes.Buffer
	code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, summaryExecutor(t, runner.Succeeded, nil, true))
	if code != 3 {
		t.Fatalf("report write failure not reflected by process: %d %s", code, errs.String())
	}
	summary := readRunSummary(t, c)
	if summary.ExecutionStatus != "COMPLETED" || summary.ReportStatus != "FAILED" || summary.ExitCode != 3 || !strings.Contains(strings.Join(summary.ReasonCodes, ","), "REPORT_WRITE_FAILED") {
		t.Fatalf("report failure conflated with execution: %#v", summary)
	}
	retained, err := os.ReadFile(filepath.Join(summary.EvidenceDirectory, "result.private.json"))
	if err != nil || string(retained) != "KEEP_EXISTING_EVIDENCE" {
		t.Fatal("existing evidence replaced")
	}
}

func TestLegacyExecutionRequiresMigrationBeforeTargetInspection(t *testing.T) {
	for _, version := range []string{auditconfig.Version, auditconfig.PortableVersion} {
		t.Run(version, func(t *testing.T) {
			c, file, _ := portableSetup(t)
			c.Version, c.InstallationState = version, ""
			c.Target = filepath.Join(filepath.Dir(c.Target), "missing-target-must-not-be-probed")
			if version == auditconfig.Version {
				c.ToolchainCatalog = ""
				c.RulePackRoot = filepath.Join(filepath.Dir(c.Target), "rules")
				c.DockerScanCodeProvider = filepath.Join(filepath.Dir(file), "scancode.json")
			}
			writeJSONTest(t, file, c)
			before, _ := os.ReadFile(file)
			var out, errs bytes.Buffer
			called := false
			code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, strings.NewReader("yes\n"), &out, &errs, func(context.Context, runner.HostRunner, runner.ExecutionSpec, adapter.Manifest, string, string, string, string) (runner.ToolExecution, error) {
				called = true
				return runner.ToolExecution{}, errors.New("must not execute")
			})
			if code != 3 || called || !strings.Contains(errs.String(), "MIGRATION_REQUIRED") || strings.Contains(out.String(), "RUN ") {
				t.Fatalf("legacy execution escaped migration boundary: %d %s %s", code, out.String(), errs.String())
			}
			after, _ := os.ReadFile(file)
			if !bytes.Equal(before, after) {
				t.Fatal("migration refusal modified original configuration")
			}
			assertNoRuns(t, c)
		})
	}
}

func TestInstallationChangeInvalidatesConfirmedPlan(t *testing.T) {
	for _, samePath := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-path", true: "new-identity-same-path"}[samePath], func(t *testing.T) {
			c, file, _ := portableSetup(t)
			var out, errs bytes.Buffer
			var calls []string
			input := &confirmationInput{output: &out, before: func() {
				if samePath {
					// Deliberately replace this test-owned installation generation.
					if err := os.Rename(c.InstallationState, c.InstallationState+"-old"); err != nil {
						t.Fatal(err)
					}
				} else {
					c.InstallationState = filepath.Join(filepath.Dir(c.InstallationState), "other-installation")
				}
				if _, err := installation.Initialize(c.InstallationState); err != nil {
					t.Fatal(err)
				}
				writeJSONTest(t, file, c)
			}}
			code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, input, &out, &errs, sentinel(t, &calls))
			if code != 5 || len(calls) != 0 || !strings.Contains(errs.String(), "STALE_PREVIEW") {
				t.Fatalf("changed installation was not part of approval: %d %s", code, errs.String())
			}
			assertNoRuns(t, c)
		})
	}
}

func TestPendingInstallationBlocksBeforeConfirmationWithoutWritingAudit(t *testing.T) {
	c, file, _ := portableSetup(t)
	state, err := installation.Open(c.InstallationState)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := state.Lock(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := runner.LoadDockerProviderConfig(c.DockerBaseProvider, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = lease.Begin("previous-synthetic-audit", "pao-synthetic-pending", "npipe:////./pipe/dockerDesktopLinuxEngine", provider.RuntimeImage, provider.DockerPath, provider.DockerSHA256)
	closeErr := lease.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("prepare durable pending run: %v %v", err, closeErr)
	}
	var out, errs bytes.Buffer
	var calls []string
	code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, sentinel(t, &calls))
	if code != 5 || len(calls) != 0 || strings.Contains(out.String(), "RUN ") || !strings.Contains(errs.String(), "POLICY_BLOCKED") {
		t.Fatalf("pending installation escaped admission: %d %s %s", code, out.String(), errs.String())
	}
	assertNoRuns(t, c)
	pending, err := state.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("audit refusal modified pending evidence: %#v %v", pending, err)
	}
}

func TestProfileToolsDoesNotExposeMutableSelection(t *testing.T) {
	ids, err := ProfileTools("secrets")
	if err != nil {
		t.Fatal(err)
	}
	ids[0] = "injected"
	again, err := ProfileTools("secrets")
	if err != nil || len(again) != 1 || again[0] != "gitleaks" {
		t.Fatal("caller changed audit profile")
	}
	if _, err := ProfileTools("invented"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestLegacyPreviewStillReadsHistoricalConfiguration(t *testing.T) {
	c, file, _ := portableSetup(t)
	c.Version, c.InstallationState = auditconfig.PortableVersion, ""
	writeJSONTest(t, file, c)
	var out, errs bytes.Buffer
	if code := Command(context.Background(), []string{"--config", file, "--profile", "secrets"}, strings.NewReader(""), &out, &errs); code != 0 || !strings.Contains(out.String(), "PREVIEW_ONLY") {
		t.Fatalf("historical preview unavailable: %d %s", code, errs.String())
	}
	assertNoRuns(t, c)
}
