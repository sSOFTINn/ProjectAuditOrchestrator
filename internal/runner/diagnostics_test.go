package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
)

func TestDockerRetainsStderrAlongsideJSONOnSuccessFailureAndTimeout(t *testing.T) {
	for _, code := range []int{0, 1, 127} {
		spec, _, _ := verifiedFixture(t)
		spec.OutputFile = "scanner.json"
		spec.OutputMediaType = "application/json"
		spec.successExitCodes = []int{0, 1}
		host := fixtureDockerHost(nil)
		host.runCaptured = func(_ context.Context, _ string, _ ...string) (commandOutput, error) {
			if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.OutputFile), []byte(`{"results":[]}`), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if code != 0 {
				err = scannerExit(code)
			}
			return commandOutput{stdout: []byte("private progress"), stderr: []byte("SYNTHETIC_PRIVATE_SECRET\x1b[31m")}, err
		}
		got, err := host.Launch(context.Background(), spec)
		if err != nil || string(got.RawOutput) != `{"results":[]}` || string(got.Stderr) != "SYNTHETIC_PRIVATE_SECRET\x1b[31m" || got.ExitCode == nil || *got.ExitCode != code {
			t.Fatalf("%#v %v", got, err)
		}
		if code == 127 && got.Status != Failed {
			t.Fatal("failure cleared")
		}
		if strings.Contains(got.Reason, "SYNTHETIC_PRIVATE") {
			t.Fatal("private diagnostic in public reason")
		}
	}
	spec, _, _ := verifiedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	host := fixtureDockerHost(func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	host.runCaptured = func(context.Context, string, ...string) (commandOutput, error) {
		cancel()
		return commandOutput{stderr: []byte("synthetic cancellation detail")}, errors.New("process killed")
	}
	got, err := host.Launch(ctx, spec)
	if err != nil || got.Status != Failed || got.DiagnosticCode != "CANCELLED" || len(got.Stderr) == 0 {
		t.Fatalf("cancel lost diagnostics: %#v %v", got, err)
	}
}

func TestCapturedStreamsAreBoundedAndDrain(t *testing.T) {
	b := boundedCapture{limit: 7}
	for _, part := range []string{"1234", "5678", "90"} {
		if n, err := b.Write([]byte(part)); n != len(part) || err != nil {
			t.Fatal("reader stalled")
		}
	}
	if string(b.Bytes()) != "1234567" || !b.truncated {
		t.Fatal("unbounded capture")
	}
	// Hide WriterTo on the source to exercise io.Copy's destination fast path.
	copyBuffer := boundedCapture{limit: 7}
	source := struct{ io.Reader }{strings.NewReader("1234567890")}
	if n, err := io.Copy(&copyBuffer, source); n != 10 || err != nil || string(copyBuffer.Bytes()) != "1234567" || !copyBuffer.truncated {
		t.Fatal("io.Copy bypassed the capture limit")
	}
}

func TestDockerDiagnosticsNeverReplaceMissingJSONAndTruncationIsPartial(t *testing.T) {
	for _, missing := range []bool{false, true} {
		spec, _, _ := verifiedFixture(t)
		spec.OutputFile, spec.OutputMediaType = "scanner.json", "application/json"
		host := fixtureDockerHost(nil)
		host.runCaptured = func(context.Context, string, ...string) (commandOutput, error) {
			if !missing {
				if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.OutputFile), []byte(`{"results":[]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			return commandOutput{stderr: []byte(`{"private":"not a result"}`), stderrTruncated: !missing}, nil
		}
		got, err := host.Launch(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if missing {
			if got.Status != Failed || got.DiagnosticCode != "OUTPUT_MISSING_OR_UNSAFE" || len(got.RawOutput) != 0 || len(got.Stderr) == 0 {
				t.Fatal("stderr replaced the missing native result")
			}
		} else if got.Status != Partial || got.DiagnosticCode != "OUTPUT_LIMIT" || string(got.RawOutput) != `{"results":[]}` {
			t.Fatal("truncated diagnostic became complete or lost JSON")
		}
	}
}

// Run this test binary itself as a trusted synthetic subprocess, never target code.
func TestCaptureProcessHelper(t *testing.T) {
	mode := ""
	for i, a := range os.Args {
		if a == "--pao-capture-helper" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
		}
	}
	if mode == "" {
		return
	}
	os.Stdout.WriteString(`{"synthetic":true}`)
	os.Stderr.WriteString("PRIVATE_SYNTHETIC_STDERR\x1b[31m")
	switch mode {
	case "overflow":
		block := strings.Repeat("x", 65536)
		for n := 0; n < 6; n++ {
			os.Stderr.WriteString(block)
		}
	case "stdout-overflow":
		block := strings.Repeat("x", 65536)
		for n := 0; n < 1025; n++ {
			os.Stdout.WriteString(block)
		}
	case "timeout":
		time.Sleep(30 * time.Second)
	case "failed":
		os.Exit(127)
	}
	os.Exit(0)
}

func TestRealProcessCaptureSuccessFailureOverflowAndDeadline(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failed", "overflow", "stdout-overflow", "timeout"} {
		timeout := 10 * time.Second
		if mode == "timeout" {
			timeout = 2 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		got, err := captureCommand(ctx, executable, "-test.run=^TestCaptureProcessHelper$", "--", "--pao-capture-helper", mode)
		if (mode != "stdout-overflow" && string(got.stdout) != `{"synthetic":true}`) || !strings.HasPrefix(string(got.stderr), "PRIVATE_SYNTHETIC_STDERR") {
			t.Fatalf("lost actual process streams %s: %#v %v", mode, got, err)
		}
		if mode == "success" && err != nil {
			t.Fatal(err)
		}
		if mode == "failed" && !isExitError(err) {
			t.Fatal("lost failure")
		}
		if mode == "overflow" && (len(got.stderr) != MaxDiagnosticBytes || !got.stderrTruncated) {
			t.Fatal("overflow not bounded")
		}
		if mode == "stdout-overflow" && (int64(len(got.stdout)) != maxDeclaredOutputBytes || !got.stdoutTruncated) {
			t.Fatal("stdout overflow not bounded")
		}
		if mode == "timeout" && (ctx.Err() != context.DeadlineExceeded || err == nil) {
			t.Fatal("deadline lost")
		}
		cancel()
	}
}

func TestRunnerTruncationAndPersistenceFailureRemainExplicit(t *testing.T) {
	for _, mode := range []string{"oversized", "store-error", "host-error"} {
		spec, registry, store := verifiedFixture(t)
		stderr := []byte("private synthetic diagnostics")
		if mode == "oversized" {
			stderr = []byte(strings.Repeat("x", MaxDiagnosticBytes+1))
		}
		if mode == "store-error" {
			var err error
			store, err = artifact.OpenWithLimit(t.TempDir(), 8)
			if err != nil {
				t.Fatal(err)
			}
		}
		h := &diagnosticFixtureHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, result: LaunchResult{Status: Succeeded, Reason: "fixture", MediaType: "application/json", RawOutput: []byte(`{}`), Stderr: stderr}}
		if mode == "host-error" {
			h.err = errors.New("PRIVATE_HOST_EXCEPTION")
		}
		result, err := (HostRunner{Registry: registry, Host: h, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-capture-limit", "inventory")
		if mode == "store-error" {
			if err == nil || result.Status != Failed || result.DiagnosticCode != "DIAGNOSTIC_STORAGE_FAILED" || len(result.RawArtifacts) != 1 {
				t.Fatal("storage failure cleared")
			}
		} else if mode == "oversized" {
			if err != nil || result.Status != Partial || len(result.Diagnostics) != 1 || !result.Diagnostics[0].Truncated || result.Diagnostics[0].Artifact.Size != MaxDiagnosticBytes {
				t.Fatal("overflow cleared")
			}
		} else if result.Status != Failed || result.DiagnosticCode != "HOST_START_FAILED" || len(result.Diagnostics) != 1 {
			t.Fatal("host failure lost diagnostics")
		}
	}
}

type diagnosticFixtureHost struct {
	fixtureHost
	result              LaunchResult
	err                 error
	waitForCancellation bool
}

func (h *diagnosticFixtureHost) Launch(ctx context.Context, _ ExecutionSpec) (LaunchResult, error) {
	h.launched = true
	if h.waitForCancellation {
		<-ctx.Done()
		return h.result, ctx.Err()
	}
	return h.result, h.err
}

func TestRunnerDeadlinePreservesBothStreams(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	spec.TimeoutSeconds = 1
	h := &diagnosticFixtureHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, waitForCancellation: true,
		result: LaunchResult{MediaType: "application/json", RawOutput: []byte(`{"results":[]}`), Stderr: []byte("PRIVATE_TIMEOUT_DETAIL")}}
	got, err := (HostRunner{Registry: registry, Host: h, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-timeout-diagnostic", "inventory")
	if err != nil || got.Status != TimedOut || got.DiagnosticCode != "TIMED_OUT" || len(got.RawArtifacts) != 1 || len(got.Diagnostics) != 1 {
		t.Fatalf("timeout lost evidence or negative state: %#v %v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(got.Diagnostics[0].Artifact.Path)))
	if err != nil || string(data) != "PRIVATE_TIMEOUT_DETAIL" || got.Validate() != nil {
		t.Fatal("timeout diagnostic did not persist")
	}
}

func TestRunnerPersistsDiagnosticsSeparatelyAndEmitsStages(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	h := &diagnosticFixtureHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, result: LaunchResult{Status: Failed, Reason: "synthetic failure", DiagnosticCode: "SCANNER_FAILED", MediaType: "application/json", RawOutput: []byte(`{"results":[]}`), Stderr: []byte("SYNTHETIC_PRIVATE_DETAIL")}}
	stages := []Stage{}
	outcome, err := (HostRunner{Registry: registry, Host: h, Artifacts: store, Progress: func(s Stage) { stages = append(stages, s) }}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-diagnostic", "inventory")
	if err != nil || len(outcome.RawArtifacts) != 1 || len(outcome.Diagnostics) != 1 {
		t.Fatalf("%#v %v", outcome, err)
	}
	if err := outcome.Validate(); err != nil {
		t.Fatal(err)
	}
	ref := outcome.Diagnostics[0].Artifact
	data, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(ref.Path)))
	if err != nil || string(data) != "SYNTHETIC_PRIVATE_DETAIL" || ref.ExecutionID != outcome.ID {
		t.Fatal("diagnostic evidence lost")
	}
	if len(stages) < 3 || stages[0] != StageValidate || stages[len(stages)-1] != StagePersist {
		t.Fatalf("missing lifecycle: %v", stages)
	}
}
