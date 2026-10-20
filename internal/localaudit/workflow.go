// Package localaudit implements the operator preview and confirmation workflow.
package localaudit

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type scannerExecutor func(context.Context, runner.HostRunner, runner.ExecutionSpec, adapter.Manifest, string, string, string, string) (runner.ToolExecution, error)

type preparedAudit struct {
	config       auditconfig.Config
	snapshot     target.Snapshot
	manifests    []adapter.Manifest
	plan         plan.Plan
	ids          []string
	baseHost     runner.DockerHost
	scancodeHost runner.DockerHost
	registry     *toolchain.Registry
	sbomqs       *toolchain.OwnerApprovedTool
	sbomqsError  error
	configDigest string
	catalogTools map[string]toolchain.CatalogTool
}

var profiles = map[string][]string{
	"fast":         {"trivy"},
	"deep-sca":     {"syft", "grype", "osv-scanner"},
	"license":      {"scancode", "reuse"},
	"secrets":      {"gitleaks"},
	"sast":         {"opengrep"},
	"ci-security":  {"zizmor"},
	"sbom-quality": {"syft", "sbomqs"},
	"mvp":          {"syft", "sbomqs", "grype", "osv-scanner", "scancode", "reuse", "trivy", "gitleaks", "opengrep", "zizmor"},
}

func prepare(configPath, profile string) (preparedAudit, error) {
	return prepareContext(context.Background(), configPath, profile)
}

func prepareContext(ctx context.Context, configPath, profile string) (preparedAudit, error) {
	var p preparedAudit
	ids, ok := profiles[profile]
	if !ok {
		return p, errors.New("choose --profile fast, deep-sca, license, secrets, sast, ci-security, sbom-quality or mvp")
	}
	c, err := auditconfig.Load(configPath)
	if err != nil {
		return p, err
	}
	all, err := loadManifests(c.ManifestRoot)
	if err != nil {
		return p, err
	}
	byID := map[string]adapter.Manifest{}
	for _, m := range all {
		byID[m.ID] = m
	}
	for _, id := range ids {
		m, ok := byID[id]
		if !ok {
			return p, fmt.Errorf("required declaration missing: %s", id)
		}
		if err := auditconfig.CheckPath(filepath.Join(c.ManifestRoot, id, "manifest.json"), false); err != nil {
			return p, err
		}
		p.manifests = append(p.manifests, m)
	}
	p.snapshot, err = target.SnapshotRootContext(ctx, c.Target)
	if err != nil {
		return p, err
	}
	if !p.snapshot.Complete || len(p.snapshot.ReparsePaths) != 0 {
		return p, errors.New("complete target snapshot without redirected entries is required")
	}
	p.config, p.ids = c, append([]string(nil), ids...)
	// Determine applicability before loading tool/provider dependencies. The
	// final plan below also binds the complete catalog and provider identities.
	p.plan, err = plan.BuildConfiguredFromManifests(p.snapshot, profile, c.Digest(), p.manifests)
	if err != nil {
		return p, err
	}
	if err := p.prepareToolchain(time.Now().UTC()); err != nil {
		return p, err
	}
	p.plan, err = plan.BuildConfiguredFromManifests(p.snapshot, profile, p.configDigest, p.manifests)
	if err != nil {
		return p, err
	}
	return p, nil
}

func newAuditID(now time.Time, targetPath string) (string, error) {
	var slug strings.Builder
	for _, ch := range strings.ToLower(filepath.Base(targetPath)) {
		if slug.Len() >= 32 {
			break
		}
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			slug.WriteRune(ch)
		} else if slug.Len() > 0 {
			slug.WriteByte('-')
		}
	}
	name := strings.Trim(slug.String(), "-")
	if name == "" {
		name = "project"
	}
	entropy := make([]byte, 12)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return now.UTC().Format("2006-01-02-150405") + "-" + name + "-" + hex.EncodeToString(entropy), nil
}

func confirmPhrase(id, digest string) string { return "RUN " + id + " " + digest }

// Command always previews. --execute additionally waits for a run-specific phrase;
// an empty reply, generic yes, stale phrase or EOF creates no audit directories.
func Command(ctx context.Context, args []string, input io.Reader, output, errout io.Writer) int {
	return command(ctx, args, input, output, errout, func(ctx context.Context, host runner.HostRunner, spec runner.ExecutionSpec, manifest adapter.Manifest, pd, cd, id, capability string) (runner.ToolExecution, error) {
		return host.ExecuteDeclared(ctx, spec, manifest, pd, cd, id, capability)
	})
}

func command(ctx context.Context, args []string, input io.Reader, output, errout io.Writer, executor scannerExecutor) int {
	fail := func(err error) int { fmt.Fprintf(errout, "PAO: %v\n", err); return 3 }
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(errout)
	configName := fs.String("config", "", "external private JSON file (absolute path or private config filename)")
	profile := fs.String("profile", "", "required: fast, deep-sca, license, secrets, sast, ci-security, sbom-quality, mvp")
	execute := fs.Bool("execute", false, "preview, then require the exact confirmation phrase")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if fs.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	configPath, err := auditconfig.Resolve(*configName)
	if err != nil {
		return fail(err)
	}
	p, err := prepareContext(ctx, configPath, *profile)
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	id, err := newAuditID(now, p.config.Target)
	if err != nil {
		return fail(err)
	}
	evidence := filepath.Join(p.config.EvidenceBase, now.Format("2006"), id)
	reportDir := filepath.Join(p.config.ReportBase, now.Format("2006"), id)
	// The console is private operator output; it intentionally displays paths using
	// quoted strings so control characters cannot forge preview lines.
	if _, err := fmt.Fprintf(output, "Попередній перегляд PAO\nАудит: %s\nПроєкт: %q\nТип перевірки: %s\nДокази: %q\nЗвіт: %q\nНалаштування: %s\nПлан: %s\nРежим: офлайн; проєкт лише для читання\n", id, p.config.Target, *profile, evidence, reportDir, p.configDigest, p.plan.PlanDigest); err != nil {
		return fail(err)
	}
	for _, node := range p.plan.Nodes {
		if _, err := fmt.Fprintf(output, "  %s: %s\n", node.ID, node.Status); err != nil {
			return fail(err)
		}
		// These fields are derived by the host planner, not scanner messages or
		// target contents. Show support gaps before asking the operator to run.
		if _, err := fmt.Fprintf(output, "    Застосовність: %s; підтримка входів: %s\n", node.Applicability, node.SupportStatus); err != nil {
			return fail(err)
		}
		for _, detail := range []struct {
			label  string
			values []string
		}{
			{"Причини обмежень", node.SupportReasons},
			{"Підтримані екосистеми", node.SupportedEcosystems},
			{"Непідтримані екосистеми", node.UnsupportedEcosystems},
		} {
			if len(detail.values) > 0 {
				if _, err := fmt.Fprintf(output, "    %s: %s\n", detail.label, strings.Join(detail.values, ", ")); err != nil {
					return fail(err)
				}
			}
		}
	}
	if _, err := fmt.Fprintln(output, "PREFLIGHT_REQUIRED: інструменти та ізоляція будуть перевірені перед запуском. Позитивний висновок ще не сформовано."); err != nil {
		return fail(err)
	}
	if !*execute {
		fmt.Fprintln(output, "PREVIEW_ONLY: для запуску повторіть команду з --execute та підтвердьте новий перегляд.")
		return 0
	}
	phrase := confirmPhrase(id, p.plan.PlanDigest)
	if _, err := fmt.Fprintf(output, "Для запуску введіть точно:\n%s\n", phrase); err != nil {
		return fail(err)
	}
	reply, err := confirmationLine(ctx, input)
	if err != nil || strings.TrimSuffix(strings.TrimSuffix(reply, "\n"), "\r") != phrase {
		fmt.Fprintln(errout, "CANCELLED: підтвердження не отримано; аудит не запущено.")
		return 5
	}
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(errout, "CANCELLED: аудит не запущено.")
		return 5
	}
	fresh, err := prepareContext(ctx, configPath, *profile)
	if err != nil {
		return fail(err)
	}
	if fresh.configDigest != p.configDigest || fresh.plan.PlanDigest != p.plan.PlanDigest {
		fmt.Fprintln(errout, "STALE_PREVIEW: налаштування, проєкт або декларації змінилися; потрібен новий перегляд.")
		return 5
	}
	if err := reserve(evidence, reportDir); err != nil {
		return fail(err)
	}
	privateConfig, _ := json.MarshalIndent(p.config, "", "  ")
	if err := writeOnce(filepath.Join(evidence, "config.operator.json"), privateConfig, 0o600); err != nil {
		return fail(err)
	}
	effective := struct {
		Version             string   `json:"version"`
		Profile             string   `json:"profile"`
		ConfigurationDigest string   `json:"configuration_digest"`
		TargetID            string   `json:"target_id"`
		Network             string   `json:"network"`
		TargetAccess        string   `json:"target_access"`
		Adapters            []string `json:"adapters"`
	}{"pao.dev/effective-config/v1", *profile, p.configDigest, p.snapshot.TargetID, "denied", "read-only", p.ids}
	effectiveBytes, _ := json.Marshal(effective)
	if err := writeOnce(filepath.Join(evidence, "config.effective.json"), effectiveBytes, 0o600); err != nil {
		return fail(err)
	}
	approval := struct{ AuditID, PlanDigest, ConfigDigest, TargetID, ConfirmedAt string }{id, p.plan.PlanDigest, p.configDigest, p.snapshot.TargetID, time.Now().UTC().Format(time.RFC3339Nano)}
	approvalBytes, _ := json.MarshalIndent(approval, "", "  ")
	if err := writeOnce(filepath.Join(evidence, "confirmation.json"), approvalBytes, 0o600); err != nil {
		return fail(err)
	}
	paths := auditPaths{targetRoot: p.config.Target, evidenceRoot: evidence, toolchainRoot: p.config.ToolchainRoot, rulePackRoot: p.config.RulePackRoot, auditID: id, output: output}
	record, runErr := executeAudit(ctx, paths, fresh, executor)
	fmt.Fprintln(output, "Перевіряємо докази й формуємо зведений звіт.")
	result, err := writeUnifiedReports(evidence, reportDir, fresh.plan, record, runErr, fresh.registry)
	if err != nil {
		return fail(err)
	}
	if runErr != nil {
		fmt.Fprintln(errout, "INCOMPLETE: аудит завершився з помилкою; наявні докази збережено.")
		return 4
	}
	for _, execution := range record.Executions {
		if execution.Status == runner.PolicyBlocked {
			fmt.Fprintln(errout, "POLICY_BLOCKED: один або більше інструментів не запущено.")
			return 5
		}
	}
	fmt.Fprintf(output, "%s: зведений звіт збережено; це ще не позитивний висновок аудиту.\n", result.Status)
	return 4
}

// Command has one confirmation prompt. A bounded reader goroutine lets a
// process signal end that prompt even when stdin remains open without a line.
// Embedded callers retain ownership of the reader and close it after cancel.
func confirmationLine(ctx context.Context, input io.Reader) (string, error) {
	type lineResult struct {
		line string
		err  error
	}
	ready := make(chan lineResult, 1)
	go func() {
		reader := bufio.NewReader(io.LimitReader(input, 512))
		line, err := reader.ReadString('\n')
		ready <- lineResult{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-ready:
		return result.line, result.err
	}
}

func reserve(evidence, reportDir string) error {
	for _, path := range []string{evidence, reportDir} {
		if err := auditconfig.CheckPath(path, true); err != nil {
			return err
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("audit output already exists or is inaccessible")
		}
	}
	for _, path := range []string{evidence, reportDir} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := auditconfig.CheckPath(filepath.Dir(path), false); err != nil {
			return err
		}
		if err := auditconfig.MakePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

// Private details are persisted first; SUMMARY is the final report artifact.
// Failure never overwrites/deletes raw evidence or an existing report.
func writeUnifiedReports(evidence, reportDir string, lock plan.Plan, record runner.Record, runErr error, registry *toolchain.Registry) (auditresult.Result, error) {
	if registry == nil {
		return auditresult.Result{}, errors.New("verified toolchain registry is unavailable")
	}
	result := auditresult.Build(evidence, lock, record, registry, runErr != nil)
	files, err := result.Files()
	if err != nil {
		return result, err
	}
	for _, item := range []struct {
		path string
		data []byte
	}{
		{filepath.Join(evidence, "result.private.json"), files.PrivateJSON},
		{filepath.Join(evidence, "findings.private.jsonl"), files.FindingsJSONL},
		{filepath.Join(reportDir, "06_report", "report.json"), files.PortableJSON},
		{filepath.Join(reportDir, "06_report", "SUMMARY.md"), files.Summary},
	} {
		if err := auditconfig.CheckPath(item.path, true); err != nil {
			return result, err
		}
		if err := writeOnce(item.path, item.data, 0o600); err != nil {
			return result, err
		}
	}
	return result, nil
}
