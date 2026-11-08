package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

func TestRuntimeApprovalRejectsPlaceholders(t *testing.T) {
	for _, value := range []string{"", "  ", "UNAPPROVED", " unapproved ", "REPLACE_WITH_OWNER", "pending", "owner\nline"} {
		a := fixtureApproval()
		a.Owner = value
		if a.Validate(time.Now()) == nil {
			t.Fatalf("placeholder owner accepted: %q", value)
		}
		a = fixtureApproval()
		a.ID = value
		if a.Validate(time.Now()) == nil {
			t.Fatalf("placeholder ID accepted: %q", value)
		}
	}
}

func TestPreparationRequiresExplicitConfirmationBeforeWrites(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	if _, err := VerifyPreparation(context.Background(), PreparationSpec{InstallationState: root}); err == nil {
		t.Fatal("unconfirmed preparation accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("unconfirmed preparation created state")
	}
}

func TestReadOnlyRuntimeCheckDoesNotCreateNativeGeneration(t *testing.T) {
	s, err := installation.Initialize(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	provider := DockerProviderConfig{APIVersion: DockerProviderConfigVersion, DockerPath: filepath.Join(t.TempDir(), "docker"), DockerSHA256: "sha256:" + strings.Repeat("a", 64), RuntimeImage: fixtureImage, RuntimeApproval: fixtureApproval()}
	_, err = CheckPreparedRuntime(context.Background(), provider, s.Root())
	if err == nil || !strings.Contains(err.Error(), "SETUP_REQUIRED") {
		t.Fatalf("missing prepared generation accepted: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(s.Root(), "native"))
	if err != nil || len(entries) != 0 {
		t.Fatal("read-only doctor prepared native state")
	}
}

func TestPreparationCapabilityRefusesTargetAndArguments(t *testing.T) {
	a := preparationAdmission{image: fixtureImage, dockerDigest: fixtureImage, probePath: "probe", probeDigest: fixtureImage, target: "synthetic", scratch: "scratch", createdAt: time.Now()}
	s := ExecutionSpec{AdapterID: "pao-preparation", ToolID: "pao-preparation", ToolPath: "probe", ToolDigest: fixtureImage, RuntimeDigest: fixtureImage, TargetRoot: "synthetic", TemporaryDir: "scratch", Arguments: []string{"synthetic", "scratch"}, Environment: map[string]string{"PAO_PROVIDER_FIXTURE": "1"}, MemoryMB: 256, MaxOutputBytes: 1024, TimeoutSeconds: 60}
	if err := a.validate(s); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ExecutionSpec){func(s *ExecutionSpec) { s.TargetRoot = "private-project" }, func(s *ExecutionSpec) { s.Arguments = []string{"--read", "private-project"} }, func(s *ExecutionSpec) { s.StatePath = "unreviewed-state" }, func(s *ExecutionSpec) {
		s.Environment = map[string]string{"PAO_PROVIDER_FIXTURE": "1", "DOCKER_HOST": "remote"}
	}} {
		changed := s
		mutate(&changed)
		if a.validate(changed) == nil {
			t.Fatal("broadened preparation capability accepted")
		}
	}
}

func TestPreparationTimeoutRequiresStartedLifecycleEvidence(t *testing.T) {
	result := LaunchResult{Status: TimedOut, DiagnosticCode: "TIMED_OUT", lifecycleID: strings.Repeat("a", 32)}
	if err := verifyPreparationOutput("timeout", result); err == nil {
		t.Fatal("startup timeout was accepted without a running probe")
	}
	result.containerStarted = true
	if err := verifyPreparationOutput("timeout", result); err != nil {
		t.Fatal(err)
	}
	result.lifecycleID = ""
	if err := verifyPreparationOutput("timeout", result); err == nil {
		t.Fatal("timeout accepted without verified lifecycle cleanup")
	}
}
