package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

type PreparationSpec struct {
	DockerPath, DockerSHA256, RuntimeImage, InstallationState string
	ProbePath, ProbeSHA256, SandboxPath, SandboxSHA256        string
	Confirmed                                                 bool
}

type PreparationCheck struct {
	Name             string `json:"name"`
	Status           string `json:"status"`
	Detail           string `json:"detail,omitempty"`
	LifecycleID      string `json:"lifecycle_id,omitempty"`
	ContainerStarted bool   `json:"container_started,omitempty"`
}

type PreparationResult struct {
	Version        string             `json:"version"`
	Status         string             `json:"status"`
	EvidenceDigest string             `json:"evidence_digest,omitempty"`
	RuntimeImage   string             `json:"runtime_image"`
	DockerSHA256   string             `json:"docker_sha256"`
	ProbeSHA256    string             `json:"probe_sha256"`
	CheckedAt      time.Time          `json:"checked_at"`
	Checks         []PreparationCheck `json:"checks"`
}

// This unexported capability can only be created by VerifyPreparation. It does
// not claim that an owner reviewed the production runtime or any scanner.
type preparationAdmission struct {
	image, dockerDigest, probePath, probeDigest, target, scratch string
	createdAt                                                    time.Time
}

func (a *preparationAdmission) validate(s ExecutionSpec) error {
	if a == nil || time.Since(a.createdAt) > 15*time.Minute || s.AdapterID != "pao-preparation" || s.ToolID != "pao-preparation" || s.ToolPath != a.probePath || s.ToolDigest != a.probeDigest || s.RuntimeDigest != a.image || s.TargetRoot != a.target || s.TemporaryDir != a.scratch || len(s.Arguments) != 2 || s.Arguments[0] != a.target || s.Arguments[1] != a.scratch || s.StatePath != "" || s.InputPath != "" || s.DatabasePath != "" || s.RulePackPath != "" || s.OutputFile != "" || len(s.AdditionalOutputs) != 0 || s.Environment["PAO_PROVIDER_FIXTURE"] != "1" || len(s.Environment) > 2 || s.MemoryMB != 256 || s.MaxOutputBytes != 1024 || s.TimeoutSeconds < 1 || s.TimeoutSeconds > 60 {
		return errors.New("preparation request exceeded its fixed synthetic capability")
	}
	for key, value := range s.Environment {
		if key == "PAO_PROVIDER_FIXTURE" && value == "1" {
			continue
		}
		if key != "PAO_QUOTA_FIXTURE" || (value != "bytes" && value != "entries" && value != "stream" && value != "timeout") {
			return errors.New("unsupported preparation mode")
		}
	}
	return nil
}

// VerifyPreparation executes only the bundled probe against new synthetic
// inputs under the installation state. It cannot receive a user target or argv.
func VerifyPreparation(ctx context.Context, spec PreparationSpec) (PreparationResult, error) {
	r := PreparationResult{Version: "pao.dev/preparation-verification/v1", Status: "BLOCKED", RuntimeImage: spec.RuntimeImage, DockerSHA256: spec.DockerSHA256, ProbeSHA256: spec.ProbeSHA256, CheckedAt: time.Now().UTC(), Checks: []PreparationCheck{}}
	if !spec.Confirmed {
		return r, errors.New("preparation verification requires explicit confirmation")
	}
	if err := validateImageID(spec.RuntimeImage); err != nil {
		return r, err
	}
	if err := verifyRegularFileDigest(spec.ProbePath, spec.ProbeSHA256); err != nil {
		return r, fmt.Errorf("bundled preparation probe: %w", err)
	}
	if err := installation.CheckReady(spec.InstallationState); err != nil {
		return r, err
	}
	if _, err := readPreparedCLI(spec.InstallationState, spec.DockerSHA256); err != nil {
		return r, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return r, err
	}
	id := "setup-" + hex.EncodeToString(nonce[:])
	root := filepath.Join(spec.InstallationState, id)
	if err := auditconfig.MakePrivateDirectory(root); err != nil {
		return r, err
	}
	targetRoot, scratch := filepath.Join(root, "target"), filepath.Join(root, "scratch")
	for _, path := range []string{targetRoot, scratch} {
		if err := auditconfig.MakePrivateDirectory(path); err != nil {
			return r, err
		}
	}
	if err := os.WriteFile(filepath.Join(targetRoot, "sentinel.txt"), []byte("unchanged"), 0600); err != nil {
		return r, err
	}
	host := DockerHost{DockerPath: spec.DockerPath, DockerSHA256: spec.DockerSHA256, RuntimeImage: spec.RuntimeImage, InstallationState: spec.InstallationState, AuditID: id, SandboxPath: spec.SandboxPath, SandboxSHA256: spec.SandboxSHA256}
	host.preparation = &preparationAdmission{image: spec.RuntimeImage, dockerDigest: spec.DockerSHA256, probePath: spec.ProbePath, probeDigest: spec.ProbeSHA256, target: targetRoot, scratch: scratch, createdAt: time.Now()}
	execution := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "pao-preparation", ToolID: "pao-preparation", ToolPath: spec.ProbePath, ToolDigest: spec.ProbeSHA256, RuntimeDigest: spec.RuntimeImage, TargetRoot: targetRoot, TemporaryDir: scratch, Arguments: []string{targetRoot, scratch}, Environment: map[string]string{"PAO_PROVIDER_FIXTURE": "1"}, TimeoutSeconds: 60, MemoryMB: 256, MaxOutputBytes: 1024, Sandbox: SandboxProperties{Isolation: StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true}}
	for _, mode := range []string{"isolation", "bytes", "entries", "stream", "timeout"} {
		current := execution
		current.Environment = map[string]string{"PAO_PROVIDER_FIXTURE": "1"}
		if mode != "isolation" {
			current.Environment["PAO_QUOTA_FIXTURE"] = mode
		}
		if mode == "timeout" {
			// Launch includes CLI freezing, VM probes and container creation. Give
			// that bounded startup work room before cancelling the bundled probe,
			// whose fixed timeout scenario sleeps for twenty seconds. The result
			// must also prove that its owned container was running before teardown.
			current.TimeoutSeconds = 10
		}
		current.ContainerName = id + "-" + mode
		result, err := host.Launch(ctx, current)
		check := PreparationCheck{Name: mode, Status: "FAIL", LifecycleID: result.lifecycleID, ContainerStarted: result.containerStarted}
		if err == nil {
			err = verifyPreparationOutput(mode, result)
		}
		if err == nil {
			check.Status = "PASS"
		} else {
			check.Detail = "synthetic isolation, bounds or teardown verification failed"
		}
		r.Checks = append(r.Checks, check)
		if err != nil {
			r.Status = "FAILED"
			return r, err
		}
	}
	data, err := os.ReadFile(filepath.Join(targetRoot, "sentinel.txt"))
	if err != nil || string(data) != "unchanged" {
		r.Status = "FAILED"
		return r, errors.New("synthetic target changed")
	}
	if _, err := os.Stat(filepath.Join(targetRoot, "must-not-write")); !os.IsNotExist(err) {
		r.Status = "FAILED"
		return r, errors.New("synthetic target accepted a write")
	}
	if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
		r.Status = "FAILED"
		return r, errors.New("synthetic scratch escaped the VM")
	}
	r.Status = "VERIFIED"
	raw, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	sum := sha256.Sum256(raw)
	r.EvidenceDigest = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

func verifyPreparationOutput(mode string, result LaunchResult) error {
	switch mode {
	case "isolation":
		var observed map[string]bool
		if result.Status != Succeeded || json.Unmarshal(result.RawOutput, &observed) != nil {
			return errors.New("synthetic probe did not complete")
		}
		for _, name := range []string{"non_root", "private_input_read", "network_denied", "target_read_only", "temporary_write_only"} {
			if !observed[name] {
				return errors.New("synthetic control failed: " + name)
			}
		}
	case "bytes", "entries":
		var observed struct {
			Exhausted bool  `json:"quota_exhausted"`
			Written   int64 `json:"written_bytes"`
			Entries   int   `json:"entries"`
		}
		if json.Unmarshal(result.RawOutput, &observed) != nil || !observed.Exhausted || observed.Written > 1<<20 || observed.Entries >= 4096 || result.Status != Failed {
			return errors.New("synthetic scratch quota was not enforced")
		}
	case "stream":
		if result.Status != Partial || result.DiagnosticCode != "OUTPUT_LIMIT" || len(result.RawOutput) != 1024 {
			return errors.New("synthetic stream limit was not enforced")
		}
	case "timeout":
		if result.Status != TimedOut || result.DiagnosticCode != "TIMED_OUT" || !result.containerStarted || result.lifecycleID == "" {
			return errors.New("synthetic deadline did not prove a running probe followed by verified teardown")
		}
	default:
		return errors.New("unknown synthetic control")
	}
	return nil
}
