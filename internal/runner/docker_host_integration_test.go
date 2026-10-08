package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func TestDockerHostSyntheticIsolationAcceptance(t *testing.T) {
	if os.Getenv("PAO_DOCKER_INTEGRATION") != "1" {
		t.Skip("set PAO_DOCKER_INTEGRATION=1 to run the local Docker Desktop acceptance test")
	}
	docker := dockerBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fixtureRoot := repositoryPath(t, "testdata", "container-vm-fixture")
	fixtureTool := filepath.Join(t.TempDir(), "pao-container-vm-fixture")
	buildGo := exec.CommandContext(ctx, goBinary(t), "build", "-trimpath", "-ldflags=-s -w", "-o", fixtureTool, filepath.Join(fixtureRoot, "main.go"))
	buildGo.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := buildGo.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic Linux fixture: %v: %s", err, output)
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	runID := hex.EncodeToString(nonce[:])
	imageName := "pao-container-vm-fixture-" + runID
	host := testDockerHost(t, docker, "")
	prepared, release, err := host.prepareExecution(ctx, ExecutionSpec{TemporaryDir: filepath.Join(t.TempDir(), "private-scratch")})
	if err != nil {
		t.Fatalf("prepare approved native Docker CLI and supervisor: %v", err)
	}
	host, ok := prepared.(DockerHost)
	if !ok {
		t.Fatal("prepared Docker host changed type")
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("release frozen native executables: %v", err)
		}
	}()
	if existing, err := host.command(ctx, "image", "ls", "--filter", "reference="+imageName, "--format", "{{.ID}}"); err != nil || len(strings.TrimSpace(string(existing))) != 0 {
		t.Fatalf("cannot prove synthetic image tag is unused: %v", err)
	}
	if output, err := host.command(ctx, "build", "--network", "none", "--pull=false", "--no-cache", "--label", "pao.synthetic-run="+runID, "-t", imageName, fixtureRoot); err != nil {
		t.Fatalf("build local scratch runtime: %v: %s", err, output)
	}
	defer func() {
		// Remove only this run's unique tag, never an image referenced by any
		// pre-existing/shared tag. The unique label also gives a distinct image ID.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := host.command(cleanupCtx, "image", "rm", imageName); err != nil {
			t.Errorf("remove exact synthetic image tag %s: %v", imageName, err)
		}
	}()
	imageIDBytes, err := host.command(ctx, "image", "inspect", "--format", "{{.Id}}", imageName)
	if err != nil {
		t.Fatal(err)
	}
	imageID := strings.TrimSpace(string(imageIDBytes))
	host.RuntimeImage = imageID
	host.RuntimeApproval.EvidenceDigest = imageID

	targetRoot := filepath.Join(t.TempDir(), "private-target")
	if err := auditconfig.MakePrivateDirectory(targetRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetRoot, "sentinel.txt"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporaryDir := filepath.Join(t.TempDir(), "private-scratch")
	if err := auditconfig.MakePrivateDirectory(temporaryDir); err != nil {
		t.Fatal(err)
	}
	statePath, stateDigest := syntheticPreparedState(t, "provider-fixture")
	capabilities, err := host.Capabilities(ctx)
	if err != nil || capabilities.Validate() != nil {
		t.Fatalf("Docker Desktop did not prove required controls: %#v %v", capabilities, err)
	}
	spec := ExecutionSpec{
		APIVersion:     "pao.dev/execution/v1alpha1",
		AdapterID:      "provider-fixture",
		ToolID:         "provider-fixture",
		ToolPath:       fixtureTool,
		StatePath:      statePath,
		StateDigest:    stateDigest,
		Arguments:      []string{targetRoot, temporaryDir},
		TargetRoot:     targetRoot,
		TemporaryDir:   temporaryDir,
		Environment:    map[string]string{"PAO_PROVIDER_FIXTURE": "1", "PAO_PROVIDER_STATE_FIXTURE": "1"},
		TimeoutSeconds: 60,
		ContainerName:  "pao-fixture-" + runID,
		Sandbox:        strongSandbox(),
	}
	toolBytes, err := os.ReadFile(fixtureTool)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(toolBytes)
	spec.ToolDigest = "sha256:" + hex.EncodeToString(digest[:])
	registry, err := toolchain.New([]toolchain.Record{{ID: "provider-fixture", Version: "1", SHA256: hex.EncodeToString(digest[:]), SourceLicense: "MIT", Redistribution: "user-installed-only", StateSHA256: strings.TrimPrefix(stateDigest, "sha256:"), StateAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), StateEnvironment: spec.Environment}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).Execute(ctx, spec, recordDigest, recordDigest, "docker-provider-fixture", "synthetic-isolation")
	if err != nil || outcome.Status != Succeeded || len(outcome.RawArtifacts) != 1 {
		t.Fatalf("synthetic isolated launch failed: %#v %v", outcome, err)
	}
	raw, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(outcome.RawArtifacts[0].Path)))
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]bool
	if err := json.Unmarshal(raw, &evidence); err != nil || !evidence["network_denied"] || !evidence["target_read_only"] || !evidence["temporary_write_only"] || !evidence["state_read_only"] || !evidence["non_root"] || !evidence["private_input_read"] {
		t.Fatalf("synthetic isolation evidence invalid: %q %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(targetRoot, "must-not-write")); !os.IsNotExist(err) {
		t.Fatalf("target was modified: %v", err)
	}
	if entries, err := os.ReadDir(temporaryDir); err != nil || len(entries) != 0 {
		t.Fatalf("scanner scratch escaped onto the host: %v", err)
	}
	if runtime.GOOS == "linux" {
		for path, mode := range map[string]os.FileMode{
			targetRoot: 0700, temporaryDir: 0700,
			filepath.Join(targetRoot, "sentinel.txt"): 0600,
		} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("private fixture permissions changed at %s: %v", path, err)
			}
		}
	}
	for _, mode := range []string{"bytes", "entries", "stream", "timeout"} {
		t.Run("bounded-"+mode, func(t *testing.T) {
			bounded := spec
			bounded.StatePath, bounded.StateDigest = "", ""
			bounded.ContainerName = "pao-fixture-" + runID + "-" + mode
			bounded.MaxOutputBytes = 1024
			bounded.Environment = map[string]string{"PAO_PROVIDER_FIXTURE": "1", "PAO_QUOTA_FIXTURE": mode}
			if mode == "timeout" {
				bounded.TimeoutSeconds = 1
			}
			result, err := host.Launch(ctx, bounded)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "bytes", "entries":
				var observed struct {
					Exhausted bool  `json:"quota_exhausted"`
					Written   int64 `json:"written_bytes"`
					Entries   int   `json:"entries"`
				}
				if json.Unmarshal(result.RawOutput, &observed) != nil || !observed.Exhausted || observed.Written > scratchBudget(bounded) || observed.Entries >= 4096 || result.Status != Failed {
					t.Fatalf("quota not enforced: %#v %#v", result, observed)
				}
			case "stream":
				if result.Status != Partial || result.DiagnosticCode != "OUTPUT_LIMIT" || len(result.RawOutput) != 1024 {
					t.Fatalf("stream limit not enforced: %#v", result)
				}
			case "timeout":
				if result.Status != TimedOut || result.DiagnosticCode != "TIMED_OUT" {
					t.Fatalf("deadline not enforced: %#v", result)
				}
			}
			if entries, err := os.ReadDir(temporaryDir); err != nil || len(entries) != 0 {
				t.Fatal("undeclared scanner writes reached the host")
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer probeCancel()
			remaining, err := host.command(probeCtx, "container", "ls", "--all", "--filter", "name=^/"+regexp.QuoteMeta(bounded.ContainerName)+"$", "--format", "{{.ID}}")
			if err != nil || len(strings.TrimSpace(string(remaining))) != 0 {
				t.Fatalf("cannot prove owned container was removed: %q %v", remaining, err)
			}
		})
	}
}

func dockerBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("PAO_DOCKER_PATH"); path != "" {
		return path
	}
	for _, path := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Docker", "Docker", "resources", "bin", "docker.exe"),
		"docker",
	} {
		if path == "docker" {
			if resolved, err := exec.LookPath(path); err == nil {
				return resolved
			}
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("Docker CLI is not available")
	return ""
}

func goBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("PAO_GO_PATH"); path != "" {
		return path
	}
	path, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("Go executable is not on PATH; set PAO_GO_PATH")
	}
	return path
}

func repositoryPath(t *testing.T, elements ...string) string {
	t.Helper()
	parts := append([]string{"..", ".."}, elements...)
	path, err := filepath.Abs(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func testDockerHost(t *testing.T, docker, image string) DockerHost {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	supervisor := filepath.Join(t.TempDir(), "pao-sandbox-linux-amd64")
	command := exec.CommandContext(ctx, goBinary(t), "build", "-trimpath", "-buildvcs=false", "-o", supervisor, "./cmd/pao-sandbox")
	command.Dir = repositoryPath(t)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build PAO supervisor: %v: %s", err, output)
	}
	digest := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return DockerHost{DockerPath: docker, DockerSHA256: digest(docker), SandboxPath: supervisor, SandboxSHA256: digest(supervisor), RuntimeImage: image, RuntimeApproval: RuntimeApproval{ID: "synthetic-local-acceptance", Owner: "PAO maintainer synthetic test", EvidenceDigest: image, ExpiresAt: time.Now().UTC().Add(time.Hour)}}
}
