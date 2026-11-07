package doctor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func sum(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func jsonFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, raw)
}

func fixture(t *testing.T) (string, auditconfig.Config, dependencies) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"config", "state", "evidence", "reports", "tools", "manifests", "target", "rules"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := auditconfig.Config{Version: auditconfig.InstallationVersion, Target: filepath.Join(root, "target"), EvidenceBase: filepath.Join(root, "evidence"), ReportBase: filepath.Join(root, "reports"), ToolchainRoot: filepath.Join(root, "tools"), RulePackRoot: filepath.Join(root, "rules"), ManifestRoot: filepath.Join(root, "manifests"), InstallationState: filepath.Join(root, "state"), ToolchainCatalog: filepath.Join(root, "config", "catalog.json"), DockerBaseProvider: filepath.Join(root, "config", "provider.json")}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	tool := []byte("synthetic scanner bytes, never executable")
	write(t, filepath.Join(c.ToolchainRoot, "gitleaks"), tool)
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "synthetic-reviewer", ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Tools: []toolchain.CatalogTool{{Record: toolchain.Record{ID: "gitleaks", Version: "8.30.1", SHA256: sum(tool), SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: strings.Repeat("a", 64), RuntimeAt: now.Add(-time.Hour)}, Binary: "gitleaks", Provider: "base"}}}
	jsonFile(t, c.ToolchainCatalog, catalog)
	cli := filepath.Join(root, "docker")
	write(t, cli, []byte("synthetic docker bytes, never executable"))
	provider := runner.DockerProviderConfig{APIVersion: runner.DockerProviderConfigVersion, DockerPath: cli, DockerSHA256: "sha256:" + sum([]byte("synthetic docker bytes, never executable")), RuntimeImage: "sha256:" + strings.Repeat("a", 64), RuntimeApproval: runner.RuntimeApproval{ID: "synthetic-review", Owner: "synthetic-reviewer", EvidenceDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: now.Add(time.Hour)}}
	jsonFile(t, c.DockerBaseProvider, provider)
	if err := os.Mkdir(filepath.Join(c.ManifestRoot, "gitleaks"), 0700); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join("..", "..", "adapters", "gitleaks", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(c.ManifestRoot, "gitleaks", "manifest.json"), manifest)
	configPath := filepath.Join(root, "config", "audit.json")
	jsonFile(t, configPath, c)
	supervisor := filepath.Join(root, "pao-sandbox-linux-amd64")
	write(t, supervisor, []byte("synthetic supervisor, never executed"))
	d := dependencies{now: func() time.Time { return now }, producer: func() (buildinfo.Producer, error) { return syntheticProducer(), nil }, runtime: func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error) {
		return runner.SandboxProperties{}, nil
	}, stateReady: func(string) error { return nil }, privatePath: func(path string, directory bool) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if directory != info.IsDir() {
			return errors.New("wrong path kind")
		}
		return nil
	}, platform: func() error { return nil }, supervisor: supervisor, superHash: "sha256:" + sum([]byte("synthetic supervisor, never executed"))}
	return configPath, c, d
}

func treeBytes(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if entry.IsDir() {
			result[rel] = "directory"
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[rel] = sum(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReadinessDoesNotWriteOrClaimAuditSuccess(t *testing.T) {
	path, c, d := fixture(t)
	write(t, filepath.Join(c.Target, "private.txt"), []byte("synthetic target must remain untouched"))
	before, _ := json.Marshal(treeBytes(t, filepath.Dir(filepath.Dir(path))))
	result := inspect(context.Background(), path, "secrets", d)
	if result.Status != "READY" {
		t.Fatalf("readiness failed: %+v", result.Checks)
	}
	if result.TargetInspected || result.ScannerStarted || result.NetworkAccess || result.IsolationTested || result.Scope != "profile-prerequisites" {
		t.Fatal("readiness overclaims execution or audit scope")
	}
	after, _ := json.Marshal(treeBytes(t, filepath.Dir(filepath.Dir(path))))
	if string(before) != string(after) {
		t.Fatal("doctor changed the installation")
	}
}

func TestReadinessAggregatesMissingTools(t *testing.T) {
	path, _, d := fixture(t)
	result := inspect(context.Background(), path, "mvp", d)
	missing := 0
	for _, check := range result.Checks {
		if check.Status == "SETUP_REQUIRED" && strings.HasPrefix(check.ID, "tool.") && strings.Count(check.ID, ".") == 1 {
			missing++
		}
	}
	if result.Status != "SETUP_REQUIRED" || missing != 9 {
		t.Fatalf("expected every missing prerequisite, got %d: %+v", missing, result.Checks)
	}
}

func TestReadinessRejectsEnvironmentOutsideAdapterContract(t *testing.T) {
	path, c, d := fixture(t)
	raw, err := os.ReadFile(c.ToolchainCatalog)
	if err != nil {
		t.Fatal(err)
	}
	var catalog toolchain.Catalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	catalog.Tools[0].Record.StateEnvironment = map[string]string{"UNDECLARED_SETTING": "value"}
	jsonFile(t, c.ToolchainCatalog, catalog)
	result := inspect(context.Background(), path, "secrets", d)
	for _, check := range result.Checks {
		if check.ID == "tool.gitleaks.contract" && check.Status == "SETUP_REQUIRED" {
			return
		}
	}
	t.Fatalf("unlaunchable adapter environment reported ready: %+v", result)
}

func TestReadinessDriftAndPendingRecoveryPreventReady(t *testing.T) {
	path, c, d := fixture(t)
	write(t, filepath.Join(c.ToolchainRoot, "gitleaks"), []byte("changed scanner"))
	d.stateReady = func(string) error { return errors.New("pending container") }
	d.runtime = func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error) {
		t.Fatal("runtime must not be probed with unresolved state")
		return runner.SandboxProperties{}, nil
	}
	result := inspect(context.Background(), path, "secrets", d)
	failed := map[string]bool{}
	for _, check := range result.Checks {
		if check.Status != "READY" {
			failed[check.ID] = true
		}
	}
	if !failed["installation.journal"] || !failed["tool.gitleaks.binary"] || result.Status != "SETUP_REQUIRED" {
		t.Fatalf("missing separate drift/recovery diagnostics: %+v", result)
	}
}

func TestReadinessNeverInspectsPrerequisitesInsideTarget(t *testing.T) {
	path, c, d := fixture(t)
	c.ToolchainRoot = c.Target
	jsonFile(t, path, c)
	d.runtime = func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error) {
		t.Fatal("unsafe configuration reached runtime")
		return runner.SandboxProperties{}, nil
	}
	result := inspect(context.Background(), path, "secrets", d)
	for _, check := range result.Checks {
		if check.ID == "tool.gitleaks.binary" {
			t.Fatal("doctor followed configuration into target")
		}
	}
	if result.Status != "SETUP_REQUIRED" {
		t.Fatal("overlapping target trusted as installation")
	}
}

func TestReadinessRequiresMigrationButDoesNotRewriteLegacy(t *testing.T) {
	path, c, d := fixture(t)
	c.Version = auditconfig.PortableVersion
	c.InstallationState = ""
	jsonFile(t, path, c)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := inspect(context.Background(), path, "secrets", d)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "SETUP_REQUIRED" || string(before) != string(after) {
		t.Fatal("legacy config silently accepted or rewritten")
	}
}

func TestCapsuleChecksMembershipHashesLimitsAndCancellation(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "rules.yml"), []byte("synthetic rule"))
	manifest := capsuleManifest{APIVersion: "pao.dev/input-capsule/v1alpha1", AdapterID: "opengrep", Kind: "rule-pack", Files: []capsuleEntry{{Path: "rules.yml", SHA256: sum([]byte("synthetic rule"))}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "pao-input-manifest.json"), raw)
	digest := "sha256:" + sum(raw)
	if err := verifyCapsule(context.Background(), root, "rules", digest, "opengrep"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "undeclared.txt"), []byte("extra"))
	if err := verifyCapsule(context.Background(), root, "rules", digest, "opengrep"); err == nil {
		t.Fatal("undeclared capsule file accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyFile(ctx, filepath.Join(root, "rules.yml"), "sha256:"+sum([]byte("synthetic rule")), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if err := verifyFile(context.Background(), filepath.Join(root, "rules.yml"), "sha256:"+sum([]byte("synthetic rule")), 2); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestCapsuleRejectsPathEscapeBeforeReadingOutside(t *testing.T) {
	root := t.TempDir()
	raw := []byte(`{"api_version":"pao.dev/prepared-state/v1alpha1","adapter_id":"reuse","files":[{"path":"../outside","sha256":"` + strings.Repeat("a", 64) + `"}]}`)
	write(t, filepath.Join(root, "pao-state-manifest.json"), raw)
	if err := verifyCapsule(context.Background(), root, "state", "sha256:"+sum(raw), "reuse"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestPreparedDatabaseProvenanceDoesNotPreventReadiness(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "db"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic database")
	write(t, filepath.Join(root, "db", "trivy.db"), payload)
	// This is the metadata envelope produced by online setup. Provenance is
	// authenticated with the complete manifest rather than fetched by doctor.
	raw := []byte(`{"schema":"pao.dev/toolchain-database-metadata/v1","tool":"trivy","files":[{"path":"db/trivy.db","sha256":"` + sum(payload) + `"}],"built_at":"2026-11-07T10:00:00Z","source":{"version":"pao.dev/database-download-lock/v1","tool":"trivy","url":"https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:synthetic"},"archive_sha256":"` + strings.Repeat("a", 64) + `"}`)
	write(t, filepath.Join(root, "metadata.json"), raw)
	if err := verifyCapsule(context.Background(), root, "database", "sha256:"+sum(raw), "trivy"); err != nil {
		t.Fatalf("setup database rejected: %v", err)
	}
	write(t, filepath.Join(root, "db", "trivy.db"), []byte("changed database"))
	if err := verifyCapsule(context.Background(), root, "database", "sha256:"+sum(raw), "trivy"); err == nil {
		t.Fatal("provenance bypassed actual database verification")
	}
}
