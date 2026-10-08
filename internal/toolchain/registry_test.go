package toolchain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func TestPreflightRecordsUnavailableAndStaleCoverage(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.Preflight(Requirement{ToolID: "missing", Capability: "inventory"}, now); got.Status != "UNAVAILABLE" {
		t.Fatalf("missing tool looked available: %#v", got)
	}
	if got := registry.Preflight(Requirement{ToolID: "fixture", Capability: "vulnerability", RequiresDatabase: true, MaximumDatabaseAge: 24 * time.Hour}, now); got.Status != "PARTIAL" {
		t.Fatalf("missing DB metadata looked complete: %#v", got)
	}
	if got := registry.Preflight(Requirement{ToolID: "fixture", Capability: "sast", RequiresState: true, MaximumStateAge: 24 * time.Hour}, now); got.Status != "PARTIAL" || got.ReasonCode != ReasonStateMissing {
		t.Fatalf("missing prepared state looked complete: %#v", got)
	}
}

func TestPreflightRejectsStalePreparedState(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed", StateSHA256: digest("manifest"), StateAt: now.Add(-25 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	got := registry.Preflight(Requirement{ToolID: "fixture", Capability: "sast", RequiresState: true, MaximumStateAge: 24 * time.Hour}, now)
	if got.Status != "PARTIAL" || got.ReasonCode != ReasonStateStale {
		t.Fatalf("stale prepared state looked available: %#v", got)
	}
}

func TestPreflightPrerequisiteTimestampBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	prerequisites := []struct {
		name        string
		requirement Requirement
		set         func(*Record, time.Time)
		missing     string
		stale       string
	}{
		{"database", Requirement{RequiresDatabase: true, MaximumDatabaseAge: MaximumPrerequisiteAge}, func(r *Record, at time.Time) { r.DatabaseSHA256, r.DatabaseAt = digest("db"), at }, ReasonDatabaseMissing, ReasonDatabaseStale},
		{"state", Requirement{RequiresState: true, MaximumStateAge: MaximumPrerequisiteAge}, func(r *Record, at time.Time) { r.StateSHA256, r.StateAt = digest("state"), at }, ReasonStateMissing, ReasonStateStale},
		{"runtime", Requirement{RequiresRuntime: true, MaximumRuntimeAge: MaximumPrerequisiteAge}, func(r *Record, at time.Time) { r.RuntimeSHA256, r.RuntimeAt = digest("runtime"), at }, ReasonRuntimeMissing, ReasonRuntimeStale},
		{"rules", Requirement{RequiresRulePack: true, MaximumRulePackAge: MaximumPrerequisiteAge}, func(r *Record, at time.Time) { r.RulePackSHA256, r.RulePackAt = digest("rules"), at }, ReasonRulePackMissing, ReasonRulePackStale},
		{"license-data", Requirement{RequiresLicenseData: true, MaximumLicenseDataAge: MaximumPrerequisiteAge}, func(r *Record, at time.Time) { r.LicenseDataSHA256, r.LicenseDataAt = digest("licenses"), at }, ReasonLicenseDataMissing, ReasonLicenseDataStale},
	}
	for _, prerequisite := range prerequisites {
		for _, scenario := range []struct {
			name   string
			at     time.Time
			reason string
		}{
			{"missing", time.Time{}, prerequisite.missing},
			{"future", now.Add(time.Nanosecond), prerequisite.stale},
			{"expired", now.Add(-MaximumPrerequisiteAge - time.Nanosecond), prerequisite.stale},
			{"boundary", now.Add(-MaximumPrerequisiteAge), ""},
			{"current", now, ""},
		} {
			t.Run(prerequisite.name+"/"+scenario.name, func(t *testing.T) {
				record := Record{ID: "fixture", Version: "1", SHA256: digest("binary"), SourceLicense: "MIT", Redistribution: "user-installed"}
				prerequisite.set(&record, scenario.at)
				registry, err := New([]Record{record})
				if err != nil {
					t.Fatal(err)
				}
				requirement := prerequisite.requirement
				requirement.ToolID, requirement.Capability = "fixture", "inventory"
				got := registry.Preflight(requirement, now)
				status := "AVAILABLE_NOT_STARTED"
				if scenario.reason != "" {
					status = "PARTIAL"
				}
				if got.Status != status || got.ReasonCode != scenario.reason {
					t.Fatalf("unexpected freshness coverage: %#v", got)
				}
				if got := registry.Preflight(Requirement{ToolID: "fixture", Capability: "inventory"}, now); got.Status != "AVAILABLE_NOT_STARTED" {
					t.Fatalf("unused prerequisite blocked preflight: %#v", got)
				}
			})
		}
	}
}

func TestPreflightRequiresRuntimeRulePackAndLicenseDataIndependently(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		requirement Requirement
		reason      string
	}{
		{Requirement{ToolID: "fixture", Capability: "sast", RequiresRuntime: true}, ReasonRuntimeMissing},
		{Requirement{ToolID: "fixture", Capability: "sast", RequiresRulePack: true}, ReasonRulePackMissing},
		{Requirement{ToolID: "fixture", Capability: "license", RequiresLicenseData: true}, ReasonLicenseDataMissing},
	}
	for _, tc := range cases {
		got := registry.Preflight(tc.requirement, now)
		if got.Status != "PARTIAL" || got.ReasonCode != tc.reason {
			t.Fatalf("missing prerequisite did not remain explicit: %#v", got)
		}
	}
}

func TestRegistryBindsProductionPrerequisiteDigests(t *testing.T) {
	runtimeDigest := digest("runtime")
	ruleDigest := digest("rules")
	licenseDigest := digest("license-data")
	registry, err := New([]Record{{
		ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed",
		RuntimeSHA256: runtimeDigest, RulePackSHA256: ruleDigest, LicenseDataSHA256: licenseDigest,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyRuntimeDigest("fixture", "sha256:"+runtimeDigest); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyRulePackDigest("fixture", "sha256:"+ruleDigest); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyLicenseDataDigest("fixture", "sha256:"+licenseDigest); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyRulePackDigest("fixture", "sha256:"+digest("other")); err == nil {
		t.Fatal("unapproved rule pack passed registry verification")
	}
}

func TestVerifyFileUsesPinnedChecksumWithoutExecutingTool(t *testing.T) {
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture-tool")
	if err := os.WriteFile(path, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyFile("fixture", path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyFile("fixture", path); err == nil {
		t.Fatal("modified tool passed pinned checksum verification")
	}
}

func TestVerifyStateDigestRequiresExactApprovedManifestDigest(t *testing.T) {
	state := digest("state-manifest")
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed", StateSHA256: state}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyStateDigest("fixture", "sha256:"+state); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyStateDigest("fixture", "sha256:"+digest("other-state")); err == nil {
		t.Fatal("unapproved prepared state passed registry verification")
	}
}

func TestVerifyPreparedStateRequiresExactApprovedEnvironment(t *testing.T) {
	state := digest("state-manifest")
	approved := map[string]string{"HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed", StateSHA256: state, StateEnvironment: approved}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyPreparedState("fixture", "sha256:"+state, map[string]string{"HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyPreparedState("fixture", "sha256:"+state, map[string]string{"HOME": "/pao/state"}); err == nil {
		t.Fatal("missing prepared-state environment was accepted")
	}
	if err := registry.VerifyPreparedState("fixture", "sha256:"+state, map[string]string{"HOME": "/pao/state", "SEMGREP_LOG_FILE": "/tmp/log"}); err == nil {
		t.Fatal("changed prepared-state environment was accepted")
	}
}

func TestRegistryCopiesApprovedPreparedStateEnvironment(t *testing.T) {
	environment := map[string]string{"HOME": "/pao/state"}
	state := digest("state-manifest")
	registry, err := New([]Record{{ID: "fixture", Version: "1.0.0", SHA256: digest("binary"), SourceLicense: "Apache-2.0", Redistribution: "user-installed", StateSHA256: state, StateEnvironment: environment}})
	if err != nil {
		t.Fatal(err)
	}
	environment["HOME"] = "/changed"
	if err := registry.VerifyPreparedState("fixture", "sha256:"+state, map[string]string{"HOME": "/pao/state"}); err != nil {
		t.Fatalf("registry retained caller-owned environment map: %v", err)
	}
}

func TestCoverageReasonsStayMachineReadableAndIncomplete(t *testing.T) {
	coverage := Coverage{ToolID: "fixture", Capability: "inventory", Status: "UNAVAILABLE", ReasonCode: ReasonToolUnverified, Reason: "fixture"}
	if err := coverage.Validate(); err != nil || coverage.Complete() {
		t.Fatalf("coverage reason was not explicit/incomplete: %#v %v", coverage, err)
	}
	coverage.ReasonCode = "PASS"
	if err := coverage.Validate(); err == nil {
		t.Fatal("unknown coverage reason code was accepted")
	}
}

func TestExplicitPrerequisiteGapsNeverLookComplete(t *testing.T) {
	for _, code := range []string{ReasonToolMissing, ReasonDatabaseMissing, ReasonStateMissing, ReasonRulePackMissing, ReasonIsolationMismatch, ReasonTimedOut} {
		coverage, err := ExplicitGap("fixture", "inventory", code, "synthetic gap")
		if err != nil || coverage.Complete() || coverage.ReasonCode != code {
			t.Fatalf("gap was not explicit: %#v %v", coverage, err)
		}
	}
}
