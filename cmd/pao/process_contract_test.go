package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

// These tests execute built entry points, not main's helper functions. All audits
// use an empty invented target and a not-applicable zizmor declaration. There is
// no Docker provider, installed scanner, target-code execution or network use.
func TestProcessContracts(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	buildRoot := t.TempDir()
	primary := processBuild(t, repository, buildRoot, "pao-a", "./cmd/pao", "0.0.0-process-a")
	second := processBuild(t, repository, buildRoot, "pao-b", "./cmd/pao", "0.0.0-process-b")
	compatibility := processBuild(t, repository, buildRoot, "pao-local", "./cmd/pao-local-audit", "0.0.0-process-a")
	helper := processBuild(t, repository, buildRoot, "process-fixture", "./cmd/pao/testdata/process-fixture", "0.0.0-process-rebuild")
	identityA := processDoctor(t, primary)
	identityB := processDoctor(t, second)
	if identityA.ExecutableSHA256 == identityB.ExecutableSHA256 {
		t.Fatal("different PAO builds have the same executable identity")
	}
	t.Logf("built producer A=%s B=%s", identityA.ExecutableSHA256, identityB.ExecutableSHA256)

	t.Run("help-without-reading-config-or-target", func(t *testing.T) {
		fixture := processFixture(t, repository)
		for _, args := range [][]string{
			{"--help"}, {"-h"}, {"help"},
			{"inspect", "--target", filepath.Join(fixture.target, "missing"), "--help"},
			{"plan", "--target", filepath.Join(fixture.target, "missing"), "--help"},
			{"audit", "--config", fixture.invalid, "--execute", "--help"},
			{"audit", "--target", filepath.Join(fixture.target, "missing"), "--no-adapters", "--help"},
		} {
			result := processInvoke(t, primary, args, "", nil)
			if len(args) > 1 {
				processExpect(t, result, 0, "Usage of "+args[0]+":")
				continue
			}
			processExpect(t, result, 0, "PAO")
			if result.stderr != "" || !strings.Contains(result.stdout, "RUN <audit-id> <plan-digest>") {
				t.Fatalf("global help is missing the approval boundary: %#v", result)
			}
		}
		processExpect(t, processInvoke(t, primary, []string{"unknown-command"}, "", nil), exitUsage, "PAO")
		fixture.assertNoRuns(t)
	})

	var firstRun processRunArtifacts
	var parserVersion string
	for _, entry := range []struct {
		name, binary string
		prefix       []string
	}{
		{"primary", primary, []string{"audit"}},
		{"second-build", second, []string{"audit"}},
		{"compatibility", compatibility, nil},
	} {
		// Keep the first run alive until the later independent rebuild process.
		fixture := processFixture(t, repository)
		t.Run(entry.name, func(t *testing.T) {
			args := append(append([]string{}, entry.prefix...), "--config", fixture.config, "--profile", "ci-security")
			preview := processInvoke(t, entry.binary, args, "", nil)
			processExpect(t, preview, 0, "PREVIEW_ONLY")
			fixture.assertNoRuns(t)
			invalid := append(append([]string{}, entry.prefix...), "--config", fixture.invalid, "--profile", "ci-security")
			processExpect(t, processInvoke(t, entry.binary, invalid, "", nil), 3, "PAO:")
			fixture.assertNoRuns(t)
			execute := append(append([]string{}, args...), "--execute")
			oldPhrase := ""
			for _, input := range []string{"", "yes\n"} {
				refusal := processInvoke(t, entry.binary, execute, input, nil)
				processExpect(t, refusal, 5, "CANCELLED")
				for _, line := range strings.Split(refusal.stdout, "\n") {
					if strings.HasPrefix(line, "RUN ") {
						oldPhrase = strings.TrimSuffix(line, "\r")
					}
				}
				fixture.assertNoRuns(t)
			}
			if oldPhrase == "" {
				t.Fatal("refused process did not display a run-specific phrase")
			}
			processExpect(t, processInvoke(t, entry.binary, execute, oldPhrase+"\n", nil), 5, "CANCELLED")
			fixture.assertNoRuns(t)
			result := processInvoke(t, entry.binary, execute, "", func(_ *exec.Cmd, stdin io.WriteCloser, phrase string) error {
				_, err := io.WriteString(stdin, phrase+"\n")
				return err
			})
			processExpect(t, result, 4, "REVIEW_REQUIRED")
			artifacts := fixture.readRun(t)
			wantHash := processDigest(t, entry.binary)
			if artifacts.record.Producer == nil || artifacts.record.Producer.ExecutableSHA256 != wantHash {
				t.Fatal("run record is not bound to the executable actually launched")
			}
			for _, report := range []auditresult.PortableReport{artifacts.report, artifacts.private.Portable()} {
				if report.Status != "REVIEW_REQUIRED" || report.RunProducerStatus != "RECORDED" || report.ReportProducerStatus != "RECORDED" || report.RunProducer == nil || report.ReportProducer == nil || report.RunProducer.ExecutableSHA256 != wantHash || report.ReportProducer.ExecutableSHA256 != wantHash {
					t.Fatalf("process/report producer or status mismatch: %#v", report)
				}
				if len(report.Coverage) != 1 || report.Coverage[0].ParsingStatus != "NOT_APPLICABLE" {
					t.Fatalf("synthetic run unexpectedly requested scanner coverage: %#v", report.Coverage)
				}
			}
			if len(artifacts.record.Executions) != 1 || artifacts.record.Executions[0].Status != runner.Unsupported || len(artifacts.record.Executions[0].RawArtifacts) != 0 {
				t.Fatal("not-applicable synthetic run produced scanner results")
			}
			if parserVersion == "" {
				parserVersion, firstRun = artifacts.report.ParserVersion, artifacts
			} else if artifacts.report.ParserVersion != parserVersion {
				t.Fatal("producer comparison did not use the same parser version")
			}
			t.Logf("actual_exit=%d status=%s parser=%s producer=%s", result.code, artifacts.report.Status, parserVersion, wantHash)
		})
	}

	t.Run("legacy-no-adapters", func(t *testing.T) {
		fixture := processFixture(t, repository)
		result := processInvoke(t, primary, []string{"audit", "--target", fixture.target, "--no-adapters"}, "", nil)
		processExpect(t, result, 4, "INCOMPLETE")
		var legacy struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(result.stdout), &legacy); err != nil || legacy.Status != "INCOMPLETE" {
			t.Fatalf("legacy process result: %v %s", err, result.stdout)
		}
		fixture.assertNoRuns(t)
	})

	t.Run("shell-wrapper-preserves-native-exit", func(t *testing.T) {
		fixture := processFixture(t, repository)
		var shell string
		var prefix []string
		if runtime.GOOS == "windows" {
			shell, err = exec.LookPath("pwsh")
			prefix = []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", filepath.Join(repository, "cmd", "pao", "testdata", "process-wrapper.ps1"), primary}
		} else {
			shell, err = exec.LookPath("sh")
			prefix = []string{filepath.Join(repository, "cmd", "pao", "testdata", "process-wrapper.sh"), primary}
		}
		if err != nil {
			t.Fatalf("process wrapper shell is required: %v", err)
		}
		for _, tc := range []struct {
			args   []string
			code   int
			marker string
		}{
			{[]string{"audit", "--config", fixture.config, "--profile", "ci-security"}, 0, "PREVIEW_ONLY"},
			{[]string{"audit", "--config", fixture.invalid, "--profile", "ci-security"}, 3, "PAO:"},
			{[]string{"audit", "--config", fixture.config, "--profile", "ci-security", "--execute"}, 5, "CANCELLED"},
			{[]string{"audit", "--target", fixture.target, "--no-adapters"}, 4, "INCOMPLETE"},
		} {
			processExpect(t, processInvoke(t, shell, append(append([]string{}, prefix...), tc.args...), "", nil), tc.code, tc.marker)
		}
		fixture.assertNoRuns(t)
	})

	t.Run("rebuild-preserves-original-and-historical-unknown", func(t *testing.T) {
		if firstRun.recordPath == "" {
			t.Fatal("first synthetic run was not produced")
		}
		before := processDigest(t, firstRun.recordPath)
		for _, historical := range []bool{false, true} {
			recordPath := firstRun.recordPath
			if historical {
				old := firstRun.record
				old.Producer = nil
				recordPath = filepath.Join(t.TempDir(), "historical-synthetic-record.json")
				processWriteJSON(t, recordPath, old)
			}
			result := processInvoke(t, helper, []string{"rebuild", filepath.Dir(firstRun.recordPath), firstRun.lockPath, recordPath}, "", nil)
			processExpect(t, result, 0, "report_producer")
			var report auditresult.PortableReport
			if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
				t.Fatal(err)
			}
			if report.ReportProducer == nil || report.ReportProducer.ExecutableSHA256 != processDigest(t, helper) || report.ParserVersion != parserVersion {
				t.Fatal("rebuilt report does not identify its actual producer and parser")
			}
			if historical {
				if report.RunProducer != nil || report.RunProducerStatus != "UNKNOWN_HISTORICAL" {
					t.Fatal("historical run producer was invented")
				}
			} else if report.RunProducer == nil || *report.RunProducer != *firstRun.record.Producer || report.RunProducer.ExecutableSHA256 == report.ReportProducer.ExecutableSHA256 {
				t.Fatal("report rebuild replaced the original run producer")
			}
		}
		if processDigest(t, firstRun.recordPath) != before {
			t.Fatal("report rebuild mutated original evidence")
		}
	})

	t.Run("context-cancel-with-open-input", func(t *testing.T) {
		fixture := processFixture(t, repository)
		result := processInvoke(t, helper, []string{"cancel", "--config", fixture.config, "--profile", "ci-security", "--execute"}, "", func(_ *exec.Cmd, stdin io.WriteCloser, _ string) error {
			_, err := io.WriteString(stdin, "cancel\n")
			return err
		})
		processExpect(t, result, 5, "CANCELLED")
		fixture.assertNoRuns(t)
	})
	if runtime.GOOS != "windows" {
		for _, binary := range []string{primary, compatibility} {
			t.Run("interrupt-open-stdin-"+filepath.Base(binary), func(t *testing.T) {
				fixture := processFixture(t, repository)
				args := []string{"--config", fixture.config, "--profile", "ci-security", "--execute"}
				if binary == primary {
					args = append([]string{"audit"}, args...)
				}
				result := processInvoke(t, binary, args, "", func(cmd *exec.Cmd, _ io.WriteCloser, _ string) error { return cmd.Process.Signal(os.Interrupt) })
				processExpect(t, result, 5, "CANCELLED")
				fixture.assertNoRuns(t)
			})
		}
	} else {
		t.Log("Windows uses the native context-cancellation fixture; POSIX SIGINT cases run on Linux")
	}
}

type processFixturePaths struct{ config, invalid, target, evidence, reports string }
type processRunArtifacts struct {
	record               runner.Record
	private              auditresult.Result
	report               auditresult.PortableReport
	recordPath, lockPath string
}

func processFixture(t *testing.T, repository string) processFixturePaths {
	t.Helper()
	root := t.TempDir()
	p := processFixturePaths{config: filepath.Join(root, "config", "audit.json"), invalid: filepath.Join(root, "config", "invalid.json"), target: filepath.Join(root, "target"), evidence: filepath.Join(root, "evidence"), reports: filepath.Join(root, "reports")}
	toolsRoot := filepath.Join(root, "tools")
	for _, dir := range []string{filepath.Dir(p.config), p.target, toolsRoot} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	catalogPath := filepath.Join(filepath.Dir(p.config), "catalog.json")
	now := time.Now().UTC()
	// This unused catalog declaration is syntactically valid but has no executable.
	// Any regression that tries to launch it fails; no provider exists for it.
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "synthetic-process-test", ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Tools: []toolchain.CatalogTool{{Record: toolchain.Record{ID: "zizmor", Version: "synthetic", SHA256: strings.Repeat("a", 64), SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: strings.Repeat("b", 64), RuntimeAt: now}, Binary: "absent/scanner", Provider: "base"}}}
	processWriteJSON(t, catalogPath, catalog)
	processWriteJSON(t, p.config, auditconfig.Config{Version: auditconfig.PortableVersion, Target: p.target, EvidenceBase: p.evidence, ReportBase: p.reports, ToolchainRoot: toolsRoot, ManifestRoot: filepath.Join(repository, "adapters"), ToolchainCatalog: catalogPath})
	if err := os.WriteFile(p.invalid, []byte(`{"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p processFixturePaths) assertNoRuns(t *testing.T) {
	t.Helper()
	for _, path := range []string{p.evidence, p.reports} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("refused/preview process wrote output: %s (%v)", path, err)
		}
	}
	entries, err := os.ReadDir(p.target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("synthetic target changed: %v", err)
	}
}

func (p processFixturePaths) readRun(t *testing.T) processRunArtifacts {
	t.Helper()
	entries, err := os.ReadDir(p.target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("confirmed synthetic process changed its target: %v", err)
	}
	one := func(pattern string) string {
		paths, err := filepath.Glob(pattern)
		if err != nil || len(paths) != 1 {
			t.Fatalf("expected exactly one artifact: %s: %v %v", pattern, paths, err)
		}
		return paths[0]
	}
	r := processRunArtifacts{recordPath: one(filepath.Join(p.evidence, "*", "*", "run-record.json"))}
	r.lockPath = filepath.Join(filepath.Dir(r.recordPath), "plan.lock.json")
	processReadJSON(t, r.recordPath, &r.record)
	processReadJSON(t, filepath.Join(filepath.Dir(r.recordPath), "result.private.json"), &r.private)
	processReadJSON(t, one(filepath.Join(p.reports, "*", "*", "06_report", "report.json")), &r.report)
	return r
}

func processBuild(t *testing.T, repository, outputRoot, name, pkg, version string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(outputRoot, name)
	goPath := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goPath += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goPath, "build", "-trimpath", "-buildvcs=false", "-ldflags=-X github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo.Version="+version, "-o", output, pkg)
	cmd.Dir = repository
	cmd.Env = processEnv(map[string]string{"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"})
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, data)
	}
	return output
}

func processDoctor(t *testing.T, binary string) buildinfo.Producer {
	t.Helper()
	r := processInvoke(t, binary, []string{"doctor"}, "", nil)
	processExpect(t, r, 0, "producer")
	var doctor struct {
		Version  string             `json:"version"`
		Producer buildinfo.Producer `json:"producer"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doctor); err != nil {
		t.Fatal(err)
	}
	if doctor.Producer.Validate() != nil || doctor.Version != doctor.Producer.Version || doctor.Producer.ExecutableSHA256 != processDigest(t, binary) || doctor.Producer.IdentityStatus != "DEVELOPMENT" || doctor.Producer.Revision != "unknown" || doctor.Producer.SourceTreeSHA256 != "unknown" {
		t.Fatalf("doctor invented build identity: %#v", doctor)
	}
	return doctor.Producer
}

type processResult struct {
	code           int
	stdout, stderr string
}
type processOutput struct {
	sync.Mutex
	buffer  bytes.Buffer
	pending string
	phrase  chan string
}

func (o *processOutput) Write(data []byte) (int, error) {
	o.Lock()
	defer o.Unlock()
	n, err := o.buffer.Write(data)
	o.pending += string(data)
	for {
		line, rest, ok := strings.Cut(o.pending, "\n")
		if !ok {
			break
		}
		o.pending = rest
		if strings.HasPrefix(line, "RUN ") {
			select {
			case o.phrase <- strings.TrimSuffix(line, "\r"):
			default:
			}
		}
	}
	return n, err
}

func (o *processOutput) String() string {
	o.Lock()
	defer o.Unlock()
	return o.buffer.String()
}

func processInvoke(t *testing.T, program string, args []string, input string, onPhrase func(*exec.Cmd, io.WriteCloser, string) error) processResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	var stderr bytes.Buffer
	stdout := &processOutput{phrase: make(chan string, 1)}
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	// Audit paths must not discover installed scanners or helper programs via PATH.
	cmd.Env = processEnv(map[string]string{"PATH": "", "POWERSHELL_TELEMETRY_OPTOUT": "1"})
	if onPhrase == nil {
		cmd.Stdin = strings.NewReader(input)
	}
	var stdin io.WriteCloser
	if onPhrase != nil {
		var err error
		stdin, err = cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdin.Close()
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var runErr error
	if onPhrase != nil {
		select {
		case phrase := <-stdout.phrase:
			if err := onPhrase(cmd, stdin, phrase); err != nil {
				cancel()
				<-wait
				t.Fatal(err)
			}
			runErr = <-wait
		case runErr = <-wait:
			t.Errorf("process ended before its confirmation phrase")
		}
	} else {
		runErr = <-wait
	}
	if ctx.Err() != nil {
		t.Fatalf("process failed to stop within deadline (stdin remained open): %s %v\n%s\n%s", program, args, stdout.String(), stderr.String())
	}
	code := 0
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) {
			t.Fatal(runErr)
		}
		code = exit.ExitCode()
	}
	return processResult{code, stdout.String(), stderr.String()}
}

func processExpect(t *testing.T, r processResult, code int, marker string) {
	t.Helper()
	if r.code != code || !strings.Contains(r.stdout+r.stderr, marker) {
		t.Fatalf("actual exit=%d want=%d marker=%q\nstdout=%s\nstderr=%s", r.code, code, marker, r.stdout, r.stderr)
	}
}
func processWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func processReadJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
func processDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func processEnv(values map[string]string) []string {
	env := []string{}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		overridden := false
		for name := range values {
			if strings.EqualFold(key, name) {
				overridden = true
			}
		}
		if !overridden {
			env = append(env, item)
		}
	}
	for key, value := range values {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	return env
}
