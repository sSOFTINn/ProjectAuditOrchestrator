package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type fixtureHost struct {
	capabilities SandboxProperties
	probed       bool
	launched     bool
	launchedSpec ExecutionSpec
}

type failedOutputHost struct{}

type additionalOutputHost struct{}

func (failedOutputHost) Capabilities(context.Context) (SandboxProperties, error) {
	return strongSandbox(), nil
}
func (failedOutputHost) Launch(context.Context, ExecutionSpec) (LaunchResult, error) {
	return LaunchResult{Status: Failed, Reason: "synthetic tool failed", MediaType: "application/json", RawOutput: []byte(`{"error":"synthetic"}`)}, nil
}
func (additionalOutputHost) Capabilities(context.Context) (SandboxProperties, error) {
	return strongSandbox(), nil
}
func (additionalOutputHost) Launch(_ context.Context, spec ExecutionSpec) (LaunchResult, error) {
	for _, output := range spec.AdditionalOutputs {
		if err := os.WriteFile(filepath.Join(spec.TemporaryDir, output.File), []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
			return LaunchResult{}, err
		}
	}
	return LaunchResult{Status: NoFindings, Reason: "fixture complete", MediaType: "application/json", RawOutput: []byte(`{}`)}, nil
}

func (h *fixtureHost) Capabilities(context.Context) (SandboxProperties, error) {
	h.probed = true
	return h.capabilities, nil
}
func (h *fixtureHost) Launch(_ context.Context, spec ExecutionSpec) (LaunchResult, error) {
	h.launched = true
	h.launchedSpec = spec
	return LaunchResult{Status: NoFindings, Reason: "fixture complete", MediaType: "application/json", RawOutput: []byte(`{}`)}, nil
}

func TestHostRunnerFailsClosedBeforeAnyNativeLaunch(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	host := &fixtureHost{capabilities: strongSandbox()}
	runner := HostRunner{Registry: registry, Artifacts: store}
	outcome, err := runner.Execute(context.Background(), spec, recordDigest, recordDigest, "exec-host", "inventory")
	var capabilityError *CapabilityError
	if !errors.As(err, &capabilityError) || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("missing isolation host did not fail closed: %#v %v", outcome, err)
	}
}

func TestHostRunnerUsesOnlyVerifiedToolAndStrongHost(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	host := &fixtureHost{capabilities: strongSandbox()}
	runner := HostRunner{Registry: registry, Host: host, Artifacts: store}
	outcome, err := runner.Execute(context.Background(), spec, recordDigest, recordDigest, "exec-host", "inventory")
	if err != nil || !host.launched || outcome.Status != NoFindings || len(outcome.RawArtifacts) != 1 || outcome.Sandbox.Isolation != StrongIsolation {
		t.Fatalf("verified strong host did not retain evidence: %#v %v", outcome, err)
	}
	host.launched = false
	spec.ToolPath = filepath.Join(t.TempDir(), "unverified-tool")
	if _, err := runner.Execute(context.Background(), spec, recordDigest, recordDigest, "exec-blocked", "inventory"); err == nil || host.launched {
		t.Fatal("unverified tool was offered to isolation host")
	}
}

func TestHostRunnerPersistsDeclaredAdditionalOutput(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	spec.AdditionalOutputs = []DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}}
	outcome, err := (HostRunner{Registry: registry, Host: additionalOutputHost{}, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-extra", "inventory")
	if err != nil || len(outcome.RawArtifacts) != 2 || outcome.RawArtifacts[1].MediaType != "application/vnd.cyclonedx+json" {
		t.Fatalf("additional output was not retained: %#v %v", outcome, err)
	}
}

func TestHostRunnerRejectsTamperedPreparedStateBeforeLaunch(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, spec.AdapterID)
	if err := os.WriteFile(filepath.Join(spec.StatePath, "cache.txt"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-state", "inventory")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("tampered state was offered to host: %#v %v", outcome, err)
	}
}

func TestHostRunnerRejectsPreparedStateNotApprovedByRegistryBeforeLaunch(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, spec.AdapterID)
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-state-registry", "inventory")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("unapproved prepared state was offered to host: %#v %v", outcome, err)
	}
}

func TestHostRunnerBindsOpengrepCandidateStateAndEnvironmentBeforeLaunch(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	spec, _, store := verifiedFixture(t)
	spec.AdapterID, spec.ToolID = "opengrep", "opengrep"
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, "opengrep")
	spec.Environment = map[string]string{
		"HOME":             "/pao/state",
		"TMPDIR":           "/pao/state",
		"XDG_CACHE_HOME":   "/pao/state",
		"SEMGREP_LOG_FILE": "/pao/out/semgrep.log",
	}
	spec.RulePackPath, spec.RulePackDigest = syntheticInputCapsule(t, "opengrep", "rule-pack")
	spec.OutputFile = "opengrep.json"
	spec.OutputMediaType = "application/json"
	spec.Arguments = []string{"scan", "--config", spec.RulePackPath, "--json", "--json-output", filepath.Join(spec.TemporaryDir, spec.OutputFile), spec.TargetRoot}
	toolBytes, err := os.ReadFile(spec.ToolPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(toolBytes)
	registry, err := toolchain.New([]toolchain.Record{{ID: "opengrep", Version: "fixture", SHA256: hex.EncodeToString(sum[:]), SourceLicense: "LGPL-2.1-only", Redistribution: "user-installed-only", StateSHA256: spec.StateDigest[len("sha256:"):], StateAt: now, RulePackSHA256: spec.RulePackDigest[len("sha256:"):], RulePackAt: now, StateEnvironment: map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", "opengrep", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CompatibleToolVersions = []string{"fixture"} // This inert fixture is not the upstream scanner.
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-opengrep-state", "sast")
	if err != nil || !host.launched || outcome.Status != NoFindings || outcome.StateDigest != spec.StateDigest {
		t.Fatalf("approved Opengrep candidate was not launched: %#v %v", outcome, err)
	}
	host.launched = false
	spec.Environment["SEMGREP_LOG_FILE"] = "/tmp/unapproved.log"
	outcome, err = (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-opengrep-state-blocked", "sast")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("changed Opengrep state environment was offered to host: %#v %v", outcome, err)
	}
	host.launched = false
	spec.Environment = map[string]string{"UNDECLARED": "value"}
	outcome, err = (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-opengrep-env-blocked", "sast")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("undeclared Opengrep environment was offered to host: %#v %v", outcome, err)
	}
}

func TestHostRunnerBindsScanCodeStateEntrypointAndEnvironmentBeforeLaunch(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	spec, _, store := verifiedFixture(t)
	spec.AdapterID, spec.ToolID = "scancode", "scancode"
	spec.StatePath, spec.StateDigest = syntheticPreparedState(t, "scancode")
	spec.StateEntrypoint = "scancode-toolkit-v32.5.0/venv/bin/scancode"
	spec.Environment = map[string]string{
		"PYTHONDONTWRITEBYTECODE": "1",
		"SCANCODE_CACHE":          "/pao/out/scancode-cache",
		"SCANCODE_TEMP":           "/pao/out/scancode-tmp",
	}
	spec.OutputFile = "scancode.json"
	spec.OutputMediaType = "application/json"
	spec.Arguments = []string{"--license", "--copyright", "--package", "--processes", "1", "--timeout", "300", "--json", filepath.Join(spec.TemporaryDir, spec.OutputFile), spec.TargetRoot}
	toolBytes, err := os.ReadFile(spec.ToolPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(toolBytes)
	registry, err := toolchain.New([]toolchain.Record{{ID: "scancode", Version: "fixture", SHA256: hex.EncodeToString(sum[:]), SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", StateSHA256: spec.StateDigest[len("sha256:"):], StateAt: now, StateEnvironment: map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", "scancode", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CompatibleToolVersions = []string{"fixture"}
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-scancode-state", "license")
	if err != nil || !host.launched || outcome.Status != NoFindings || host.launchedSpec.StateEntrypoint != spec.StateEntrypoint {
		t.Fatalf("approved ScanCode candidate was not launched: %#v %#v %v", outcome, host.launchedSpec, err)
	}
	host.launched = false
	spec.Environment["SCANCODE_TEMP"] = "/tmp/unapproved"
	outcome, err = (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-scancode-state-blocked", "license")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("changed ScanCode state environment was offered to host: %#v %v", outcome, err)
	}
}

func TestHostRunnerRejectsSpecThatDoesNotMatchManifest(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	path, err := filepath.Abs(filepath.Join("..", "..", "adapters", "syft", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Host: host}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-mismatch", "inventory")
	if err == nil || outcome.Status != PolicyBlocked || outcome.ManifestDigest == "" || host.launched {
		t.Fatalf("manifest mismatch did not fail before launch: %#v %v", outcome, err)
	}
}

func TestHostRunnerRejectsArgumentsThatDoNotMatchManifest(t *testing.T) {
	spec, _, _ := verifiedFixture(t)
	spec.AdapterID, spec.ToolID = "syft", "syft"
	spec.Arguments = []string{"--dangerous-unapproved-option", spec.TargetRoot}
	path, err := filepath.Abs(filepath.Join("..", "..", "adapters", "syft", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	host := &fixtureHost{capabilities: strongSandbox()}
	outcome, err := (HostRunner{Host: host}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "exec-argv", "inventory")
	if err == nil || outcome.Status != PolicyBlocked || host.launched {
		t.Fatalf("unapproved fixed arguments reached the host: %#v %v", outcome, err)
	}
}

func TestHostRunnerRetainsRawEvidenceWhenLaunchedToolFails(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	outcome, err := (HostRunner{Registry: registry, Host: failedOutputHost{}, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-failed", "inventory")
	if err != nil || outcome.Status != Failed || len(outcome.RawArtifacts) != 1 || outcome.Coverage.Reason != "synthetic tool failed" {
		t.Fatalf("failed tool result did not retain protected raw evidence: %#v %v", outcome, err)
	}
	if err := outcome.Validate(); err != nil {
		t.Fatalf("failed result with raw evidence is invalid: %v", err)
	}
}

type freshnessFixtureHost struct {
	fixtureHost
	digest string
}

func (h *freshnessFixtureHost) RuntimeIdentity() string { return h.digest }

func TestHostRunnerEnforcesPrerequisiteFreshnessBeforeHostInvocation(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	prerequisites := []struct {
		name    string
		missing string
		stale   string
	}{
		{"database", toolchain.ReasonDatabaseMissing, toolchain.ReasonDatabaseStale},
		{"state", toolchain.ReasonStateMissing, toolchain.ReasonStateStale},
		{"runtime", toolchain.ReasonRuntimeMissing, toolchain.ReasonRuntimeStale},
		{"rules", toolchain.ReasonRulePackMissing, toolchain.ReasonRulePackStale},
		{"license-data", toolchain.ReasonLicenseDataMissing, toolchain.ReasonLicenseDataStale},
	}
	for _, prerequisite := range prerequisites {
		for _, scenario := range []struct {
			name   string
			at     time.Time
			reason string
		}{
			{"missing", time.Time{}, prerequisite.missing},
			{"future", now.Add(time.Nanosecond), prerequisite.stale},
			{"expired", now.Add(-toolchain.MaximumPrerequisiteAge - time.Nanosecond), prerequisite.stale},
			{"boundary", now.Add(-toolchain.MaximumPrerequisiteAge), ""},
			{"current", now, ""},
			{"not-declared", time.Time{}, ""},
		} {
			t.Run(prerequisite.name+"/"+scenario.name, func(t *testing.T) {
				spec, _, store := verifiedFixture(t)
				toolBytes, err := os.ReadFile(spec.ToolPath)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(toolBytes)
				// Unused catalog prerequisites remain stale. Only dependencies
				// declared by this execution may prevent its launch.
				stale := now.Add(-91 * 24 * time.Hour)
				record := toolchain.Record{
					ID: spec.ToolID, Version: "1", SHA256: hex.EncodeToString(sum[:]), SourceLicense: "MIT", Redistribution: "user-installed-only",
					DatabaseSHA256: recordDigest[7:], DatabaseAt: stale, StateSHA256: recordDigest[7:], StateAt: stale,
					RuntimeSHA256: recordDigest[7:], RuntimeAt: stale, RulePackSHA256: recordDigest[7:], RulePackAt: stale,
					LicenseDataSHA256: recordDigest[7:], LicenseDataAt: stale,
				}
				if scenario.name != "not-declared" {
					switch prerequisite.name {
					case "database":
						spec.DatabasePath, spec.DatabaseDigest = syntheticFreshnessDatabase(t)
						record.DatabaseSHA256, record.DatabaseAt = strings.TrimPrefix(spec.DatabaseDigest, "sha256:"), scenario.at
					case "state":
						spec.StatePath, spec.StateDigest = syntheticPreparedState(t, spec.AdapterID)
						record.StateSHA256, record.StateAt = strings.TrimPrefix(spec.StateDigest, "sha256:"), scenario.at
					case "runtime":
						spec.RuntimeDigest, record.RuntimeAt = recordDigest, scenario.at
					case "rules":
						spec.RulePackPath, spec.RulePackDigest = syntheticInputCapsule(t, spec.AdapterID, "rule-pack")
						record.RulePackSHA256, record.RulePackAt = strings.TrimPrefix(spec.RulePackDigest, "sha256:"), scenario.at
					case "license-data":
						spec.LicenseDataDigest, record.LicenseDataAt = recordDigest, scenario.at
					}
				}
				registry, err := toolchain.New([]toolchain.Record{record})
				if err != nil {
					t.Fatal(err)
				}
				host := &freshnessFixtureHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, digest: recordDigest}
				runner := HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}
				outcome, err := runner.Execute(context.Background(), spec, recordDigest, recordDigest, "exec-freshness", "inventory")
				if scenario.reason == "" {
					if err != nil || !host.launched || outcome.Status != NoFindings || len(outcome.RawArtifacts) != 1 {
						t.Fatalf("fresh or unused prerequisite prevented execution: %#v %v", outcome, err)
					}
				} else {
					var capabilityError *CapabilityError
					if !errors.As(err, &capabilityError) || host.probed || host.launched || outcome.Status != PolicyBlocked || outcome.Coverage.Status != PolicyBlocked || outcome.Coverage.ReasonCode != scenario.reason || outcome.DiagnosticCode != "APPROVAL_CHECK_FAILED" || len(outcome.RawArtifacts) != 0 {
						t.Fatalf("invalid prerequisite did not block before host invocation: %#v %v", outcome, err)
					}
					files, err := os.ReadDir(filepath.Join(store.Root(), "raw", "sha256"))
					if err != nil || len(files) != 0 {
						t.Fatalf("blocked execution created raw evidence: %v %v", files, err)
					}
				}
				if err := outcome.Validate(); err != nil {
					t.Fatalf("execution outcome lost valid lineage: %v", err)
				}
			})
		}
	}
}

func syntheticFreshnessDatabase(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	data := []byte("synthetic offline database")
	if err := os.WriteFile(filepath.Join(root, "data.bin"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	metadata := []byte(`{"schema":"pao.dev/toolchain-database-metadata/v1","tool":"fixture","files":[{"path":"data.bin","sha256":"` + hex.EncodeToString(sum[:]) + `"}]}`)
	if err := os.WriteFile(filepath.Join(root, databaseMetadataName), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	metadataSum := sha256.Sum256(metadata)
	return root, "sha256:" + hex.EncodeToString(metadataSum[:])
}

func verifiedFixture(t *testing.T) (ExecutionSpec, *toolchain.Registry, *artifact.Store) {
	t.Helper()
	targetRoot := t.TempDir()
	toolPath := filepath.Join(t.TempDir(), "fixture-tool")
	contents := []byte("verified fixture tool")
	if err := os.WriteFile(toolPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	registry, err := toolchain.New([]toolchain.Record{{ID: "fixture", Version: "1", SHA256: hex.EncodeToString(sum[:]), SourceLicense: "MIT", Redistribution: "user-installed-only"}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec := ExecutionSpec{APIVersion: "pao.dev/execution/v1alpha1", AdapterID: "fixture", ToolID: "fixture", ToolPath: toolPath, ToolDigest: "sha256:" + hex.EncodeToString(sum[:]), Arguments: []string{"scan", targetRoot}, TargetRoot: targetRoot, TemporaryDir: t.TempDir(), TimeoutSeconds: 60, Sandbox: strongSandbox()}
	return spec, registry, store
}
