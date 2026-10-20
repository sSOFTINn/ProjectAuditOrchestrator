package localaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestConsoleDoesNotPrintPrivateExecutionErrors(t *testing.T) {
	_, path := setup(t)
	var out, errs bytes.Buffer
	executor := func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ConfigDigest: cd, Status: runner.PolicyBlocked, DiagnosticCode: "STATE_CHECK_FAILED", Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.PolicyBlocked, Reason: "INJECT_ME_PRIVATE\x1b[31m"}}, errors.New("INJECT_ME_PRIVATE\x1b[31m")
	}
	code := command(context.Background(), []string{"--config", path, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, executor)
	if code != 5 || !strings.Contains(out.String(), "середовище не пройшло перевірку") {
		t.Fatalf("missing explanation: %d %s", code, out.String())
	}
	if strings.Contains(out.String()+errs.String(), "INJECT_ME_PRIVATE") || strings.ContainsRune(out.String(), 27) {
		t.Fatal("printed private exception")
	}
}

func setup(t *testing.T) (auditconfig.Config, string) {
	t.Helper()
	root := t.TempDir()
	c := auditconfig.Config{Version: auditconfig.Version, Target: filepath.Join(root, "demo"), EvidenceBase: filepath.Join(root, "evidence"), ReportBase: filepath.Join(root, "reports"), ToolchainRoot: filepath.Join(root, "tools"), RulePackRoot: filepath.Join(root, "rules"), ManifestRoot: filepath.Join(root, "manifests"), DockerBaseProvider: filepath.Join(root, "config", "base.json"), DockerScanCodeProvider: filepath.Join(root, "config", "scancode.json")}
	for _, p := range []string{c.Target, c.ToolchainRoot, c.RulePackRoot, c.ManifestRoot, filepath.Join(root, "config")} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	abs, _ := filepath.Abs(filepath.Join("..", "..", "adapters"))
	manifests, err := loadManifests(abs)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range manifests {
		dir := filepath.Join(c.ManifestRoot, m.ID)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.Target, "go.mod"), []byte("module synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config", "audit.json")
	docker := filepath.Join(root, "config", "docker.exe")
	if err := os.WriteFile(docker, []byte("synthetic docker"), 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("synthetic docker"))
	for _, item := range []struct{ path, image string }{{c.DockerBaseProvider, baseRuntime}, {c.DockerScanCodeProvider, scancodeRuntime}} {
		provider := runner.DockerProviderConfig{APIVersion: runner.DockerProviderConfigVersion, DockerPath: docker, DockerSHA256: "sha256:" + hex.EncodeToString(sum[:]), RuntimeImage: item.image, RuntimeApproval: runner.RuntimeApproval{ID: "test", Owner: "test", EvidenceDigest: item.image, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}
		data, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return c, path
}

// confirmationInput models a human who reads the displayed phrase before replying.
// It can change a fixture after preview to test revalidation without a real scanner.
type confirmationInput struct {
	output *bytes.Buffer
	before func()
	used   bool
	mode   string
}

func (c *confirmationInput) Read(p []byte) (int, error) {
	if c.used {
		return 0, io.EOF
	}
	c.used = true
	if c.before != nil {
		c.before()
	}
	text := ""
	for _, line := range strings.Split(c.output.String(), "\n") {
		if strings.HasPrefix(line, "RUN ") {
			text = line + "\n"
		}
	}
	if c.mode == "yes" {
		text = "yes\n"
	}
	if c.mode == "stale" {
		text = "RUN old-audit old-digest\n"
	}
	if text == "" {
		return 0, io.EOF
	}
	return copy(p, text), nil
}

func sentinel(t *testing.T, calls *[]string) scannerExecutor {
	return func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		*calls = append(*calls, s.AdapterID)
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := m.AllowsEnvironment(s.Environment); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s.ContainerName, id) || strings.Contains(s.ContainerName, "brain") {
			t.Fatal("fixed/incorrect run identity")
		}
		if err := h.Registry.VerifyToolDigest(s.ToolID, s.ToolDigest); err != nil {
			t.Fatal(err)
		}
		if err := h.Registry.VerifyRuntimeDigest(s.ToolID, s.RuntimeDigest); err != nil {
			t.Fatal(err)
		}
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.PolicyBlocked, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.PolicyBlocked, Reason: "synthetic host absent"}}, nil
	}
}
func mustManifestDigest(t *testing.T, m adapter.Manifest) string {
	t.Helper()
	d, err := adapter.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func assertNoRuns(t *testing.T, c auditconfig.Config) {
	t.Helper()
	for _, p := range []string{c.EvidenceBase, c.ReportBase} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("created run without valid approval")
		}
	}
}

func TestPreviewAndRefusalNeverLaunchOrWrite(t *testing.T) {
	for _, mode := range []string{"preview", "yes", "stale", "eof", "missing-profile", "unknown-profile", "legacy-bypass"} {
		t.Run(mode, func(t *testing.T) {
			c, path := setup(t)
			var out, errs bytes.Buffer
			var calls []string
			args := []string{"--config", path, "--profile", "deep-sca"}
			var input io.Reader = strings.NewReader("")
			if mode != "preview" {
				args = append(args, "--execute")
			}
			if mode == "yes" || mode == "stale" {
				input = &confirmationInput{output: &out, mode: mode}
			}
			if mode == "missing-profile" {
				args = []string{"--config", path}
			}
			if mode == "unknown-profile" {
				args = []string{"--config", path, "--profile", "repo-online"}
			}
			if mode == "legacy-bypass" {
				args = []string{"--target", c.Target, "--only", "syft"}
			}
			code := command(context.Background(), args, input, &out, &errs, sentinel(t, &calls))
			if mode == "preview" && code != 0 {
				t.Fatalf("preview %d: %s", code, errs.String())
			}
			if mode != "preview" && code == 0 {
				t.Fatal("unexpected success")
			}
			if len(calls) != 0 {
				t.Fatal("scanner launched")
			}
			assertNoRuns(t, c)
		})
	}
}

func TestPreviewExplainsSupportBeforeConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hasGo    bool
		filename string
		want     []string
	}{
		{
			name: "mixed-go-pypi", hasGo: true, filename: "requirements.txt",
			want: []string{"osv-scanner: PREFLIGHT_REQUIRED\n    Застосовність: APPLICABLE; підтримка входів: PARTIAL", "DB_ECOSYSTEM_UNSUPPORTED", "Підтримані екосистеми: Go", "Непідтримані екосистеми: PyPI"},
		},
		{
			name: "python-only", filename: "requirements.txt",
			want: []string{"osv-scanner: UNSUPPORTED\n    Застосовність: APPLICABLE; підтримка входів: UNSUPPORTED", "DB_ECOSYSTEM_UNSUPPORTED", "Непідтримані екосистеми: PyPI"},
		},
		{
			name: "custom-lockfile", filename: "requirements.lock",
			want: []string{"syft: PREFLIGHT_REQUIRED\n    Застосовність: APPLICABLE; підтримка входів: PARTIAL\n    Причини обмежень: UNSUPPORTED_INPUT_FORMAT", "Непідтримані екосистеми: PyPI"},
		},
	} {
		for _, execute := range []bool{false, true} {
			mode := "preview"
			if execute {
				mode = "confirmation-refused"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				c, file, _ := portableSetup(t)
				if !tc.hasGo {
					if err := os.Remove(filepath.Join(c.Target, "go.mod")); err != nil {
						t.Fatal(err)
					}
				}
				const privateMarker = "PRIVATE_PREVIEW_SENTINEL"
				if err := os.WriteFile(filepath.Join(c.Target, tc.filename), []byte("synthetic==1.0.0\n# "+privateMarker+"\x1b[31m\n"), 0600); err != nil {
					t.Fatal(err)
				}
				catalog := portableCatalogFixture(t, &c, profiles["deep-sca"])
				writeJSONTest(t, c.ToolchainCatalog, catalog)
				writeJSONTest(t, file, c)
				args := []string{"--config", file, "--profile", "deep-sca"}
				wantCode := 0
				if execute {
					args = append(args, "--execute")
					wantCode = 5
				}
				var out, errs bytes.Buffer
				var calls []string
				code := command(context.Background(), args, strings.NewReader(""), &out, &errs, sentinel(t, &calls))
				if code != wantCode {
					t.Fatalf("unexpected exit %d: %s", code, errs.String())
				}
				preview := out.String()
				if execute {
					confirmation := strings.Index(preview, "\nRUN ")
					if confirmation < 0 || !strings.Contains(errs.String(), "CANCELLED") {
						t.Fatalf("missing refused confirmation: %s %s", preview, errs.String())
					}
					preview = preview[:confirmation]
				} else if !strings.Contains(preview, "PREVIEW_ONLY") || strings.Contains(preview, "\nRUN ") {
					t.Fatalf("preview requested execution: %s", preview)
				}
				for _, want := range tc.want {
					if !strings.Contains(preview, want) {
						t.Errorf("missing %q before confirmation:\n%s", want, preview)
					}
				}
				if !tc.hasGo && strings.Contains(preview, "Підтримані екосистеми: Go") {
					t.Error("advertised absent Go ecosystem")
				}
				if strings.Contains(out.String()+errs.String(), privateMarker) || strings.ContainsRune(out.String()+errs.String(), 27) {
					t.Fatal("preview printed target content")
				}
				if len(calls) != 0 {
					t.Fatal("scanner launched")
				}
				assertNoRuns(t, c)
			})
		}
	}
}

func TestRejectsDriftAfterConfirmation(t *testing.T) {
	for _, what := range []string{"target", "config", "manifest"} {
		t.Run(what, func(t *testing.T) {
			c, path := setup(t)
			var out, errs bytes.Buffer
			var calls []string
			input := &confirmationInput{output: &out, before: func() {
				switch what {
				case "target":
					if err := os.WriteFile(filepath.Join(c.Target, "new.txt"), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				case "config":
					c.ReportBase += "-changed"
					data, _ := json.Marshal(c)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				case "manifest":
					file := filepath.Join(c.ManifestRoot, "gitleaks", "manifest.json")
					m, err := adapter.LoadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					m.DisplayName += " changed"
					data, _ := json.Marshal(m)
					if err := os.WriteFile(file, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}}
			code := command(context.Background(), []string{"--config", path, "--profile", "secrets", "--execute"}, input, &out, &errs, sentinel(t, &calls))
			if code != 5 || !strings.Contains(errs.String(), "STALE_PREVIEW") || len(calls) != 0 {
				t.Fatalf("drift accepted: %d %s", code, errs.String())
			}
			assertNoRuns(t, c)
		})
	}
}

func TestConfirmedRunHasIndependentEvidenceAndPortableSummary(t *testing.T) {
	c, path := setup(t)
	for n := 0; n < 2; n++ {
		var out, errs bytes.Buffer
		var calls []string
		code := command(context.Background(), []string{"--config", path, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, sentinel(t, &calls))
		if code != 5 || strings.Join(calls, ",") != "gitleaks" {
			t.Fatalf("unexpected execution: %d %v %s", code, calls, errs.String())
		}
	}
	runs, err := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*"))
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs: %v %v", runs, err)
	}
	for _, run := range runs {
		for _, file := range []string{"confirmation.json", "config.operator.json", "plan.lock.json", "run-record.json"} {
			if _, err := os.Stat(filepath.Join(run, file)); err != nil {
				t.Fatal(err)
			}
		}
		data, err := os.ReadFile(filepath.Join(run, "run-record.json"))
		if err != nil {
			t.Fatal(err)
		}
		var record runner.Record
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.TargetBefore.TargetID != record.TargetAfter.TargetID {
			t.Fatal("target changed")
		}
	}
	reports, _ := filepath.Glob(filepath.Join(c.ReportBase, "*", "*", "06_report", "SUMMARY.md"))
	if len(reports) != 2 {
		t.Fatal("missing report")
	}
	for _, file := range reports {
		data, _ := os.ReadFile(file)
		if bytes.Contains(data, []byte(c.Target)) || bytes.Contains(data, []byte(c.ToolchainRoot)) || !bytes.Contains(data, []byte("POLICY_BLOCKED")) {
			t.Fatal("report leaked path or hid failure")
		}
	}
}

func TestProfileMappingAndConditionalSkip(t *testing.T) {
	c, path := setup(t)
	for profile, ids := range profiles {
		p, err := prepare(path, profile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(p.ids, ",") != strings.Join(ids, ",") {
			t.Fatal("profile mismatch")
		}
		if err := plan.Verify(p.plan); err != nil {
			t.Fatal(err)
		}
	}
	var out, errs bytes.Buffer
	var calls []string
	code := command(context.Background(), []string{"--config", path, "--profile", "ci-security", "--execute"}, &confirmationInput{output: &out}, &out, &errs, sentinel(t, &calls))
	if code != 4 || len(calls) != 0 || !strings.Contains(out.String(), "SKIPPED_NOT_APPLICABLE") {
		t.Fatalf("conditional launch: %d %v %s", code, calls, errs.String())
	}
	_ = c
}

func TestSyftFailureBlocksGrypeAndContinuesOSV(t *testing.T) {
	_, path := setup(t)
	var out, errs bytes.Buffer
	var calls []string
	code := command(context.Background(), []string{"--config", path, "--profile", "deep-sca", "--execute"}, &confirmationInput{output: &out}, &out, &errs, sentinel(t, &calls))
	if code != 5 || strings.Join(calls, ",") != "syft,osv-scanner" {
		t.Fatalf("dependency failure: %d %v %s", code, calls, errs.String())
	}
}

func TestUniqueNamesAndImmutableReservation(t *testing.T) {
	seen := map[string]bool{}
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	for n := 0; n < 100; n++ {
		id, err := newAuditID(now, "demo")
		if err != nil || seen[id] || !strings.HasPrefix(id, "2026-09-03-") {
			t.Fatal("ID collision")
		}
		seen[id] = true
	}
	root := t.TempDir()
	a, b := filepath.Join(root, "evidence"), filepath.Join(root, "report")
	if err := reserve(a, b); err != nil {
		t.Fatal(err)
	}
	if err := writeOnce(filepath.Join(a, "keep"), []byte("immutable"), 0600); err != nil {
		t.Fatal(err)
	}
	if reserve(a, b) == nil {
		t.Fatal("reused old run")
	}
	if writeOnce(filepath.Join(a, "keep"), []byte("replacement"), 0600) == nil {
		t.Fatal("overwrote evidence")
	}
	data, _ := os.ReadFile(filepath.Join(a, "keep"))
	if string(data) != "immutable" {
		t.Fatal("evidence changed")
	}
}

func TestAllDeclaredExecutionsWithSyntheticRawEvidence(t *testing.T) {
	c, path := setup(t)
	workflow := filepath.Join(c.Target, ".github", "workflows")
	if err := os.MkdirAll(workflow, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflow, "synthetic.yml"), []byte("name: synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	var calls []string
	executor := func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		calls = append(calls, s.AdapterID)
		if s.AdapterID == "osv-scanner" {
			if filepath.Base(s.DatabasePath) != "2026-09-03-readable-v1" || s.DatabaseDigest != "sha256:7972609e63c4e6b3d1c5bfc61bff788e6161999bf4eea7b34dfde76171894d17" {
				t.Fatal("OSV copy must preserve the approved data identity")
			}
			if err := h.Registry.VerifyDatabase(s.ToolID, s.DatabaseDigest, s.Environment); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		// Exercise the real declaration gate with no host: it must pass argument
		// binding but stop before any external process, since tools are absent.
		declarationCheck := h
		declarationCheck.Host = nil
		check, _ := declarationCheck.ExecuteDeclared(ctx, s, m, pd, cd, id, cap)
		if check.Status != runner.PolicyBlocked || strings.Contains(check.Coverage.Reason, "arguments do not match") || strings.Contains(check.Coverage.Reason, "environment does not match") {
			t.Fatalf("declaration mismatch for %s: %#v", s.AdapterID, check)
		}
		media := s.OutputMediaType
		if media == "" {
			media = "application/json"
		}
		raw, err := h.Artifacts.PutRaw(media, []byte(`{"synthetic":true}`), id)
		if err != nil {
			t.Fatal(err)
		}
		if s.AdapterID == "grype" {
			info, err := os.Stat(s.InputPath)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("Grype did not receive saved Syft evidence")
			}
		}
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.Succeeded, Sandbox: s.Sandbox, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.Succeeded, Reason: "synthetic completion"}, RawArtifacts: []artifact.RawArtifact{raw}}, nil
	}
	code := command(context.Background(), []string{"--config", path, "--profile", "mvp", "--execute"}, &confirmationInput{output: &out}, &out, &errs, executor)
	expectedCalls := append([]string(nil), profiles["mvp"]...)
	for i, id := range expectedCalls {
		if id == "sbomqs" {
			expectedCalls = append(expectedCalls[:i], expectedCalls[i+1:]...)
			break
		}
	}
	if code != 4 || strings.Join(calls, ",") != strings.Join(expectedCalls, ",") {
		t.Fatalf("execution %d %v %s", code, calls, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*", "run-record.json"))
	if len(files) != 1 {
		t.Fatal("missing record")
	}
	data, _ := os.ReadFile(files[0])
	var record runner.Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(record.Executions) != 10 {
		t.Fatal("dropped outcome")
	}
	resultData, err := os.ReadFile(filepath.Join(filepath.Dir(files[0]), "result.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result auditresult.Result
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "INCOMPLETE" || result.CoverageComplete {
		t.Fatal("placeholder native output was treated as clean")
	}
}

func TestConfiguredCommandNormalizesNativeEvidenceAndNeverOverwritesReports(t *testing.T) {
	c, configPath := setup(t)
	var out, errs bytes.Buffer
	var rawPath string
	executor := func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		raw, err := h.Artifacts.PutRaw("application/json", []byte(`[{"RuleID":"synthetic-key","File":"C:\\private\\synthetic.txt","StartLine":1,"Secret":"PAO_SYNTHETIC_SECRET_TEST"}]`), id)
		if err != nil {
			t.Fatal(err)
		}
		rawPath = filepath.Join(h.Artifacts.Root(), filepath.FromSlash(raw.Path))
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.Succeeded, Sandbox: s.Sandbox, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.Succeeded, Reason: "synthetic"}, RawArtifacts: []artifact.RawArtifact{raw}}, nil
	}
	code := command(context.Background(), []string{"--config", configPath, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, executor)
	if code != 4 {
		t.Fatalf("%d %s", code, errs.String())
	}
	reports, _ := filepath.Glob(filepath.Join(c.ReportBase, "*", "*", "06_report", "SUMMARY.md"))
	if len(reports) != 1 {
		t.Fatal("missing summary")
	}
	summary, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(summary, []byte("Можливий секрет")) || bytes.Contains(summary, []byte("PAO_SYNTHETIC_SECRET_TEST")) || bytes.Contains(summary, []byte("synthetic.txt")) {
		t.Fatal("incorrect summary")
	}
	runs, _ := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*", "run-record.json"))
	data, err := os.ReadFile(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	var record runner.Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	p, err := prepare(configPath, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	rawBefore, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, _, err := buildRegistry(c.ToolchainRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeUnifiedReports(filepath.Dir(runs[0]), filepath.Dir(filepath.Dir(reports[0])), p.plan, record, nil, registry); err == nil {
		t.Fatal("overwrote report")
	}
	rawAfter, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawBefore, rawAfter) || !bytes.Equal(summary, after) {
		t.Fatal("changed previous evidence/report")
	}
}

func TestApprovedSBOMQSCandidateUsesOnlyCapturedCycloneDX(t *testing.T) {
	c, path := setup(t)
	binary := filepath.Join(c.ToolchainRoot, "sbomqs", "bin", "sbomqs")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("synthetic sbomqs"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("synthetic sbomqs"))
	metadata := `{"api_version":"pao.dev/owner-tool-record/v1","id":"sbomqs","version":"synthetic-1","sha256":"` + hex.EncodeToString(sum[:]) + `","source_license":"Apache-2.0","redistribution":"user-installed-only","binary":"bin/sbomqs","platform":"linux-amd64","owner":"test","approved_at":"` + time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(c.ToolchainRoot, "sbomqs", "approved-tool.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := prepare(path, "sbom-quality")
	if err != nil || p.sbomqs == nil || p.configDigest == c.Digest() {
		t.Fatalf("approved candidate was not bound to the preview: %#v %v", p.sbomqs, err)
	}
	if err := os.WriteFile(binary, []byte("tampered sbomqs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if p.registry.VerifyFile("sbomqs", binary) == nil {
		t.Fatal("candidate checksum drift was accepted")
	}
	if err := os.WriteFile(binary, []byte("synthetic sbomqs"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	var calls []string
	executor := func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		calls = append(calls, s.AdapterID)
		if err := s.Validate(); err != nil {
			t.Fatalf("unsafe candidate execution spec: %v", err)
		}
		if s.AdapterID == "sbomqs" && h.Registry.VerifyFile(s.ToolID, s.ToolPath) != nil {
			t.Fatal("candidate binary was not verified before the synthetic execution")
		}
		var raw artifact.RawArtifact
		var err error
		if s.AdapterID == "syft" {
			raw, err = h.Artifacts.PutRaw("application/vnd.syft+json", []byte(`{"schema":{"version":"16.1.3"},"artifacts":[{"name":"demo"}]}`), id)
			if err != nil {
				t.Fatal(err)
			}
			cycloneBytes, err := os.ReadFile(filepath.Join("testdata", "sbomqs", "cyclonedx.json"))
			if err != nil {
				t.Fatal(err)
			}
			cycloneDX, err := h.Artifacts.PutRaw("application/vnd.cyclonedx+json", cycloneBytes, id)
			if err != nil {
				t.Fatal(err)
			}
			return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.Succeeded, Sandbox: s.Sandbox, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.Succeeded, Reason: "synthetic"}, RawArtifacts: []artifact.RawArtifact{raw, cycloneDX}}, nil
		}
		if s.InputPath == "" || !strings.Contains(filepath.ToSlash(s.InputPath), "/raw/sha256/") || len(s.Arguments) != 4 || s.Arguments[0] != "score" || s.Arguments[2] != "--legacy" || s.Arguments[3] != "--json" {
			t.Fatal("sbomqs was not bound to protected CycloneDX evidence")
		}
		raw, err = h.Artifacts.PutRaw("application/octet-stream", []byte(`{"files":[{"avg_score":8.5}]}`), id)
		if err != nil {
			t.Fatal(err)
		}
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.Succeeded, Sandbox: s.Sandbox, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.Succeeded, Reason: "synthetic"}, RawArtifacts: []artifact.RawArtifact{raw}}, nil
	}
	var first auditresult.SBOMQualityObservation
	for attempt := 0; attempt < 10; attempt++ {
		out.Reset()
		errs.Reset()
		calls = nil
		if code := command(context.Background(), []string{"--config", path, "--profile", "sbom-quality", "--execute"}, &confirmationInput{output: &out}, &out, &errs, executor); code != 4 || strings.Join(calls, ",") != "syft,sbomqs" {
			t.Fatalf("candidate execution %d: code=%d calls=%v errors=%s", attempt, code, calls, errs.String())
		}
	}
	results, _ := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*", "result.private.json"))
	if len(results) != 10 {
		t.Fatalf("want 10 private quality results, got %d", len(results))
	}
	for index, resultPath := range results {
		data, err := os.ReadFile(resultPath)
		if err != nil {
			t.Fatal(err)
		}
		var result auditresult.Result
		if err := json.Unmarshal(data, &result); err != nil || result.Status != "INCOMPLETE" || !result.CoverageComplete || result.AnalysisCoverageComplete || result.InventoryCoverage.Adequate || len(result.SBOMQuality) != 1 || result.SBOMQuality[0].Score != 8.5 {
			t.Fatalf("quality score concealed the missing Go inventory: %#v %v", result, err)
		}
		if index == 0 {
			first = result.SBOMQuality[0]
			continue
		}
		got := result.SBOMQuality[0]
		if got.ID != first.ID || got.SBOMEvidence != first.SBOMEvidence || got.ResultEvidence != first.ResultEvidence || got.Score != first.Score {
			t.Fatalf("quality result %d changed identity: got %#v, want %#v", index, got, first)
		}
	}
}
