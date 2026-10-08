package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type admissionBarrierHost struct {
	fixtureHost
	barrier func()
}

func (h *admissionBarrierHost) Capabilities(ctx context.Context) (SandboxProperties, error) {
	if h.barrier != nil {
		h.barrier()
	}
	return h.fixtureHost.Capabilities(ctx)
}

func TestFreshnessMustStillHoldAfterInputCopyAndHostProbe(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	spec, _, store := verifiedFixture(t)
	spec.LicenseDataDigest = recordDigest
	registry, err := toolchain.New([]toolchain.Record{{ID: "fixture", Version: "1", SHA256: strings.TrimPrefix(spec.ToolDigest, "sha256:"), SourceLicense: "MIT", Redistribution: "user-installed-only", LicenseDataSHA256: strings.TrimPrefix(recordDigest, "sha256:"), LicenseDataAt: now.Add(-toolchain.MaximumPrerequisiteAge)}})
	if err != nil {
		t.Fatal(err)
	}
	host := &admissionBarrierHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, barrier: func() { now = now.Add(time.Nanosecond) }}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}).Execute(context.Background(), spec, recordDigest, recordDigest, "expiry-at-probe", "inventory")
	if err == nil || !host.probed || host.launched || outcome.Coverage.ReasonCode != toolchain.ReasonLicenseDataStale || outcome.Status != PolicyBlocked {
		t.Fatalf("expired launch was admitted: %#v %v", outcome, err)
	}
}

func TestFreshnessMustStillHoldAfterDockerLaunchRepeatsProbe(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	spec, _, store := verifiedFixture(t)
	spec.LicenseDataDigest = recordDigest
	registry, err := toolchain.New([]toolchain.Record{{ID: "fixture", Version: "1", SHA256: strings.TrimPrefix(spec.ToolDigest, "sha256:"), SourceLicense: "MIT", Redistribution: "user-installed-only", LicenseDataSHA256: strings.TrimPrefix(recordDigest, "sha256:"), LicenseDataAt: now.Add(-toolchain.MaximumPrerequisiteAge)}})
	if err != nil {
		t.Fatal(err)
	}
	launched := false
	host := fixtureDockerHost(func(context.Context, string, ...string) ([]byte, error) { launched = true; return []byte(`{}`), nil })
	control := host.runDocker
	probes := 0
	host.runDocker = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		if args[2] == "info" {
			probes++
			if probes == 2 {
				now = now.Add(time.Nanosecond)
			}
		}
		return control(ctx, path, args...)
	}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}).Execute(context.Background(), spec, recordDigest, recordDigest, "expiry-at-inner-probe", "inventory")
	if err == nil || launched || probes != 2 || outcome.Status != PolicyBlocked || outcome.Coverage.ReasonCode != toolchain.ReasonLicenseDataStale {
		t.Fatalf("inner probe crossed admission without refusal: %#v %v probes=%d", outcome, err, probes)
	}
}

func TestDeclaredExecutionRequiresVersionAndHonorsManifestLimits(t *testing.T) {
	for _, scenario := range []string{"missing-version", "unknown-version", "output-limit", "timeout-limit", "accepted"} {
		t.Run(scenario, func(t *testing.T) {
			spec, _, store := verifiedFixture(t)
			spec.AdapterID, spec.ToolID = "syft", "syft"
			spec.OutputFile, spec.OutputMediaType = "syft.json", "application/json"
			spec.AdditionalOutputs = []DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}}
			manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", "syft", "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := adapter.LoadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.CompatibleToolVersions = []string{"inert-fixture"}
			manifest.TimeoutSeconds = 60
			manifest.MaxOutputBytes = 1024
			spec.Arguments, err = ManifestArguments(manifest, spec)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := toolchain.New([]toolchain.Record{{ID: "syft", Version: "inert-fixture", SHA256: strings.TrimPrefix(spec.ToolDigest, "sha256:"), SourceLicense: "MIT", Redistribution: "user-installed-only"}})
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing-version":
				manifest.CompatibleToolVersions = nil
			case "unknown-version":
				manifest.CompatibleToolVersions = []string{"untested-version"}
			case "output-limit":
				spec.MaxOutputBytes = 1025
			case "timeout-limit":
				spec.TimeoutSeconds = 61
			}
			host := &fixtureHost{capabilities: strongSandbox()}
			// The accepted control uses one result, so no fake secondary files are needed.
			if scenario == "accepted" {
				spec.AdditionalOutputs = nil
				manifest.FixedArguments = []string{"scan", "${target}"}
				spec.Arguments = []string{"scan", spec.TargetRoot}
			}
			outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).ExecuteDeclared(context.Background(), spec, manifest, recordDigest, recordDigest, "manifest-admission", "inventory")
			if scenario == "accepted" {
				if err != nil || !host.launched || outcome.Status != NoFindings || host.launchedSpec.MaxOutputBytes != 1024 {
					t.Fatalf("declared limit control failed: %#v %v", outcome, err)
				}
			} else if err == nil || host.probed || host.launched || outcome.Status != PolicyBlocked || outcome.ID == "" || outcome.ManifestDigest == "" {
				t.Fatalf("invalid declaration reached host or lost lineage: %#v %v", outcome, err)
			}
		})
	}
}

type unconfirmedTeardownHost struct{ fixtureHost }

func (h *unconfirmedTeardownHost) Launch(ctx context.Context, spec ExecutionSpec) (LaunchResult, error) {
	h.launched = true
	h.launchedSpec = spec
	return LaunchResult{MediaType: dockerRawMediaType}, &UnconfirmedContainerCleanupError{ContainerName: "inert-fixture", Cause: errors.New("synthetic daemon outage")}
}

func TestUnconfirmedTeardownRetainsApprovedCopyAndLease(t *testing.T) {
	spec, registry, store := verifiedFixture(t)
	host := &unconfirmedTeardownHost{fixtureHost{capabilities: strongSandbox()}}
	outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "pending-teardown", "inventory")
	var pending *UnconfirmedContainerCleanupError
	if !errors.As(err, &pending) || outcome.Status != Failed || outcome.DiagnosticCode != "CONTAINER_CLEANUP_UNCONFIRMED" || !host.launched {
		t.Fatalf("uncertain teardown was hidden: %#v %v", outcome, err)
	}
	if host.launchedSpec.ToolPath == spec.ToolPath {
		t.Fatal("the original mutable input was consumed")
	}
	if _, err := os.Stat(host.launchedSpec.ToolPath); err != nil {
		t.Fatal("approved private copy was removed before teardown proof", err)
	}
	retainedInputLeases.Lock()
	cleanups := retainedInputLeases.cleanups
	retainedInputLeases.cleanups = nil
	retainedInputLeases.Unlock()
	if len(cleanups) == 0 {
		t.Fatal("no lease retained")
	}
	// The fixture has no real consumer. Its test-only teardown is now proven.
	for _, cleanup := range cleanups {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestContainerRemovalNeedsAuthoritativeAbsenceProof(t *testing.T) {
	for _, scenario := range []string{"remove-error-absent", "probe-error", "still-present"} {
		t.Run(scenario, func(t *testing.T) {
			h := fixtureDockerHost(nil)
			h.runDocker = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[2] == "rm" {
					return nil, errors.New("synthetic removal failure")
				}
				if args[2] == "container" {
					switch scenario {
					case "remove-error-absent":
						return nil, nil
					case "probe-error":
						return nil, errors.New("synthetic transport failure")
					default:
						return []byte("synthetic-container-id"), nil
					}
				}
				return nil, errors.New("unexpected command")
			}
			err := h.cleanupContainer("pao-inert-fixture")
			if (err == nil) != (scenario == "remove-error-absent") {
				t.Fatalf("wrong absence proof: %v", err)
			}
		})
	}
}
