package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/sandbox"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

const fixtureImage = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fixtureDesktopInfo = `{"OSType":"linux","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"6.6.87.2-microsoft-standard-WSL2"}`

type fakeExitError struct{}

func (fakeExitError) Error() string { return "exit status 42" }
func (fakeExitError) ExitCode() int { return 42 }

type scannerExit int

func (e scannerExit) Error() string { return "synthetic scanner exit" }
func (e scannerExit) ExitCode() int { return int(e) }

func TestFindingExitsKeepRuntimeFailuresAndMissingOutputFailed(t *testing.T) {
	for _, id := range []string{"gitleaks", "osv-scanner"} {
		path, err := filepath.Abs(filepath.Join("..", "..", "adapters", id, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := adapter.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		expected := 1
		if id == "gitleaks" {
			expected = 10
			if !strings.Contains(strings.Join(m.FixedArguments, " "), "--exit-code=10") {
				t.Fatal("missing distinct findings exit")
			}
		}
		if len(m.SuccessExitCodes) != 2 || m.SuccessExitCodes[0] != 0 || m.SuccessExitCodes[1] != expected {
			t.Fatal("incorrect manifest codes")
		}
		for _, code := range []int{1, 2, 10, 127} {
			for _, missing := range []bool{false, true} {
				spec, _, _ := verifiedFixture(t)
				spec.OutputFile = "scanner.json"
				spec.OutputMediaType = "application/json"
				spec.successExitCodes = append([]int(nil), m.SuccessExitCodes...)
				host := fixtureDockerHost(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
					if !missing {
						if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.OutputFile), []byte(`[{"synthetic":true}]`), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return []byte("private progress"), scannerExit(code)
				})
				got, err := host.Launch(context.Background(), spec)
				want := Failed
				if code == expected && !missing {
					want = Succeeded
				}
				if err != nil || got.Status != want {
					t.Fatalf("%s exit %d missing %v: %#v %v", id, code, missing, got, err)
				}
				if !missing && string(got.RawOutput) != `[{"synthetic":true}]` {
					t.Fatal("lost raw output")
				}
			}
		}
	}
}

func fixtureApproval() RuntimeApproval {
	return RuntimeApproval{ID: "fixture-review", Owner: "fixture-owner", EvidenceDigest: fixtureImage, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func fixtureDockerHost(run dockerCommand) DockerHost {
	return DockerHost{
		RuntimeImage: fixtureImage, RuntimeApproval: fixtureApproval(),
		syntheticEnvelope: fixtureEnvelope,
		connection: func() (dockerConnection, error) {
			return dockerConnection{endpoint: dockerDesktopLinuxEndpoint, user: "65532:65532"}, nil
		},
		runDocker: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if len(args) < 3 || args[0] != "--host" || args[1] != dockerDesktopLinuxEndpoint {
				return nil, errors.New("missing pinned Docker endpoint")
			}
			args = args[2:]
			if len(args) >= 2 && args[0] == "container" && args[1] == "ls" {
				return nil, nil // This synthetic host confirms its inert launch is absent.
			}
			switch strings.Join(args, " ") {
			case "info --format {{json .}}":
				return []byte(fixtureDesktopInfo), nil
			case "image inspect --format {{.Id}} " + fixtureImage:
				return []byte(fixtureImage), nil
			case "image inspect --format {{json .Config.Volumes}} " + fixtureImage:
				return []byte(`null`), nil
			}
			if run == nil {
				return nil, errors.New("synthetic Docker execution is unavailable")
			}
			if len(args) > 0 && args[0] == "run" {
				data, err := base64.RawURLEncoding.DecodeString(args[len(args)-1])
				if err != nil {
					return nil, err
				}
				var request sandbox.Request
				if err := json.Unmarshal(data, &request); err != nil {
					return nil, err
				}
				args = append(append(args[:len(args)-1:len(args)-1], request.Entrypoint), request.Arguments...)
			}
			return run(ctx, path, args...)
		},
		now: func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) },
	}
}

// Synthetic scanner callbacks supply streams/files; this test-only seam wraps
// them in the same supervisor envelope consumed by the production host.
func fixtureEnvelope(spec ExecutionSpec, captured commandOutput, err error) (commandOutput, error) {
	result := sandbox.Result{Version: sandbox.Version, Stdout: captured.stdout, Stderr: captured.stderr, StdoutTruncated: captured.stdoutTruncated, StderrTruncated: captured.stderrTruncated, Files: map[string][]byte{}}
	if int64(len(result.Stdout)) > outputBudget(spec) {
		result.Stdout = result.Stdout[:outputBudget(spec)]
		result.StdoutTruncated = true
	}
	if len(result.Stderr) > MaxDiagnosticBytes {
		result.Stderr = result.Stderr[:MaxDiagnosticBytes]
		result.StderrTruncated = true
	}
	if err == nil {
		code := 0
		result.ExitCode = &code
	} else {
		var code exitCoder
		if errors.As(err, &code) {
			n := code.ExitCode()
			result.ExitCode = &n
			err = nil
		}
	}
	names := []string{}
	if spec.OutputFile != "" {
		names = append(names, spec.OutputFile)
	}
	for _, output := range spec.AdditionalOutputs {
		names = append(names, output.File)
	}
	for _, name := range names {
		contents, readErr := readDeclaredOutput(spec.TemporaryDir, name)
		if readErr != nil {
			result.UnsafeFiles = append(result.UnsafeFiles, name)
		} else {
			result.Files[name] = contents
		}
	}
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return commandOutput{}, marshalErr
	}
	return commandOutput{stdout: data}, err
}

func TestDockerHostProvesLinuxEngineAndExactImage(t *testing.T) {
	host := fixtureDockerHost(nil)
	host.runDocker = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--host " + dockerDesktopLinuxEndpoint + " info --format {{json .}}":
			return []byte(fixtureDesktopInfo), nil
		case "--host " + dockerDesktopLinuxEndpoint + " image inspect --format {{.Id}} " + fixtureImage:
			return []byte(fixtureImage + "\n"), nil
		case "--host " + dockerDesktopLinuxEndpoint + " image inspect --format {{json .Config.Volumes}} " + fixtureImage:
			return []byte(`null`), nil
		default:
			t.Fatalf("unexpected Docker call: %#v", args)
			return nil, nil
		}
	}
	capabilities, err := host.Capabilities(context.Background())
	if err != nil || capabilities.Validate() != nil {
		t.Fatalf("valid Docker proof rejected: %#v %v", capabilities, err)
	}
}

func TestDockerHostRejectsMutableRuntimeReference(t *testing.T) {
	host := fixtureDockerHost(nil)
	host.RuntimeImage = "example.test/pao:latest"
	_, err := host.Capabilities(context.Background())
	if err == nil {
		t.Fatal("mutable runtime reference was accepted")
	}
}

func TestDockerHostLaunchUsesOnlyDeclaredMountsAndControls(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, spec.AdapterID)
	spec.RulePackPath, spec.RulePackDigest = syntheticInputCapsule(t, spec.AdapterID, "rule-pack")
	spec.Arguments = []string{"scan", "--config", spec.RulePackPath, spec.TargetRoot}
	spec.RuntimeDigest = fixtureImage
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		return []byte(`{"ok":true}`), nil
	})
	result, err := host.Launch(context.Background(), spec)
	if err != nil || result.Status != Succeeded || string(result.RawOutput) != `{"ok":true}` {
		t.Fatalf("Docker launch rejected: %#v %v", result, err)
	}
	joined := strings.Join(observed, "\n")
	for _, required := range []string{"--pull\nnever", "--log-driver\nnone", "--network\nnone", "--read-only", "--cap-drop\nALL", "--security-opt\nno-new-privileges", "--pids-limit\n128", "--memory\n1024m", "--cpus\n1.0", "--user\n65532:65532", "type=bind,src=" + spec.TargetRoot + ",dst=/pao/target,readonly", "type=bind,src=" + filepath.Dir(spec.ToolPath) + ",dst=/pao/tool,readonly", "/pao/out:rw,noexec,nosuid,nodev,size=134217728,nr_inodes=4096", "type=bind,src=" + spec.StatePath + ",dst=/pao/state,readonly", "type=bind,src=" + spec.RulePackPath + ",dst=/pao/rules,readonly"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing Docker control %q in %#v", required, observed)
		}
	}
	if strings.Contains(joined, "type=bind,src="+spec.TemporaryDir) {
		t.Fatal("scanner received a writable host volume")
	}
	if strings.Contains(joined, spec.TargetRoot+"\n") {
		t.Fatalf("unmapped target argument leaked into container command: %#v", observed)
	}
	if strings.Contains(joined, spec.RulePackPath+"\n") {
		t.Fatalf("unmapped rule-pack argument leaked into container command: %#v", observed)
	}
}

func TestDockerHostRejectsRuntimeThatDoesNotMatchExecution(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.RuntimeDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := fixtureDockerHost(nil).Launch(context.Background(), spec); err == nil {
		t.Fatal("execution was offered to an unapproved runtime image")
	}
}

func TestDockerHostPreservesRawOutputFromToolFailure(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	host := fixtureDockerHost(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("synthetic protected failure"), fakeExitError{}
	})
	result, err := host.Launch(context.Background(), spec)
	if err != nil || result.Status != Failed || string(result.RawOutput) != "synthetic protected failure" {
		t.Fatalf("failed tool output was lost: %#v %v", result, err)
	}
}

func TestDockerHostAcceptsOnlyManifestBackedFindingExitCode(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.successExitCodes = []int{0, 42}
	host := fixtureDockerHost(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`[{"finding":true}]`), fakeExitError{}
	})
	result, err := host.Launch(context.Background(), spec)
	if err != nil || result.Status != Succeeded || !strings.Contains(result.Reason, "reportable findings") {
		t.Fatalf("manifest-backed finding exit code was rejected: %#v %v", result, err)
	}
}

func TestDockerHostReturnsDeclaredOutputFileAsRawEvidence(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.OutputFile = "scanner.json"
	spec.OutputMediaType = "application/json"
	spec.Arguments = []string{"scan", filepath.Join(spec.TemporaryDir, spec.OutputFile), spec.TargetRoot}
	host := fixtureDockerHost(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.OutputFile), []byte(`{"result":"file"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return []byte("scanner progress"), nil
	})
	result, err := host.Launch(context.Background(), spec)
	if err != nil || result.MediaType != "application/json" || string(result.RawOutput) != `{"result":"file"}` {
		t.Fatalf("declared output file was not returned as raw evidence: %#v %v", result, err)
	}
}

func TestDockerHostMapsDeclaredAdditionalOutputIntoWritableMount(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.OutputFile = "syft.json"
	spec.OutputMediaType = "application/json"
	spec.AdditionalOutputs = []DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}}
	spec.Arguments = []string{
		"--output", "json=" + filepath.Join(spec.TemporaryDir, spec.OutputFile),
		"--output", "cyclonedx-json=" + filepath.Join(spec.TemporaryDir, spec.AdditionalOutputs[0].File),
	}
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.OutputFile), []byte(`{"artifacts":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(spec.TemporaryDir, spec.AdditionalOutputs[0].File), []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
			t.Fatal(err)
		}
		return nil, nil
	})
	result, err := host.Launch(context.Background(), spec)
	if err != nil || result.Status != Succeeded {
		t.Fatalf("declared outputs rejected: %#v %v", result, err)
	}
	joined := strings.Join(observed, "\n")
	for _, expected := range []string{"json=/pao/out/syft.json", "cyclonedx-json=/pao/out/syft.cdx.json"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("declared output path was not mapped to the writable mount: %#v", observed)
		}
	}
	if strings.Contains(joined, "cyclonedx-json=/pao/out\\") {
		t.Fatalf("Windows separator escaped the writable mount: %#v", observed)
	}
}

func TestDockerHostDoesNotMountUndeclaredState(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		return []byte(`{"ok":true}`), nil
	})
	if _, err := host.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(observed, "\n"), "/pao/state") {
		t.Fatal("undeclared state mount was added")
	}
}

func TestDockerHostLaunchesOnlyVerifiedStateEntrypoint(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, spec.AdapterID)
	spec.StateEntrypoint = "scancode-toolkit/venv/bin/scancode"
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		return []byte(`{"ok":true}`), nil
	})
	if _, err := host.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if observed[len(observed)-len(spec.Arguments)-1] != "/pao/state/scancode-toolkit/venv/bin/scancode" {
		t.Fatalf("state entrypoint was not used: %#v", observed)
	}
}

func TestDockerHostRejectsUndeclaredHostArgument(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.Arguments = []string{"scan", filepath.Join(t.TempDir(), "unexpected")}
	_, err := fixtureDockerHost(nil).Launch(context.Background(), spec)
	if err == nil {
		t.Fatal("undeclared host path was accepted")
	}
}

func TestDockerHostRejectsUndeclaredContainerArgument(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.Arguments = []string{"scan", "/pao/not-a-declared-mount"}
	_, err := fixtureDockerHost(nil).Launch(context.Background(), spec)
	if err == nil {
		t.Fatal("undeclared container path was accepted")
	}
}

func TestDockerHostMapsSchemePrefixedDeclaredWindowsPath(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.Arguments = []string{"scan", "dir:" + spec.TargetRoot}
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		return []byte(`{"ok":true}`), nil
	})
	if _, err := host.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(observed, "\n"), "dir:/pao/target") {
		t.Fatalf("scheme-prefixed target was not mapped: %#v", observed)
	}
}

func TestDockerHostUsesDeclaredMemoryAndContainerName(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.MemoryMB = 2048
	spec.ContainerName = "pao-fixture-r2"
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = append([]string(nil), args...)
		return []byte(`{"ok":true}`), nil
	})
	if _, err := host.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(observed, "\n")
	if !strings.Contains(joined, "--memory\n2048m") || !strings.Contains(joined, "--name\npao-fixture-r2") {
		t.Fatalf("declared resource controls missing: %#v", observed)
	}
}

func TestDockerHostSBOMQualityMountsOnlyTheDeclaredInputFile(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.AdapterID, spec.ToolID = "sbomqs", "sbomqs"
	spec.InputPath = filepath.Join(t.TempDir(), "captured.cdx.json")
	if err := os.WriteFile(spec.InputPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	spec.Arguments = []string{"score", spec.InputPath, "--legacy", "--json"}
	var observed []string
	host := fixtureDockerHost(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		observed = args
		return []byte(`{"files":[{"avg_score":8.5}]}`), nil
	})
	if _, err := host.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(observed, "\n")
	if !strings.Contains(joined, "type=bind,src="+spec.InputPath+",dst=/pao/input/captured.cdx.json,readonly") || strings.Contains(joined, "dst=/pao/target") || strings.Contains(joined, "src="+filepath.Dir(spec.InputPath)+",") {
		t.Fatalf("unexpected evidence/target mount: %v", observed)
	}
	spec.InputPath = ""
	if err := spec.Validate(); err == nil {
		t.Fatal("input-only adapter accepted a missing input")
	}
}

func TestDockerHostCleansNamedContainerAfterCancellation(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.ContainerName = "pao-fixture-timeout"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls [][]string
	host := fixtureDockerHost(func(callCtx context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 0 && args[0] == "run" {
			return nil, context.Canceled
		}
		return nil, nil
	})
	if result, err := host.Launch(ctx, spec); err != nil || result.Status != Failed || result.DiagnosticCode != "CANCELLED" {
		t.Fatalf("cancelled launch did not preserve explicit failure: %#v %v", result, err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "rm --force pao-fixture-timeout" {
		t.Fatalf("exact cancelled container was not cleaned: %#v", calls)
	}
}

func TestDockerHostRejectsExpiredRuntimeApproval(t *testing.T) {
	host := fixtureDockerHost(nil)
	host.RuntimeApproval.ExpiresAt = time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	if _, err := host.Capabilities(context.Background()); err == nil {
		t.Fatal("expired runtime approval was accepted")
	}
}
