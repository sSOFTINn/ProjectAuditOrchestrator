package localaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func portableSetup(t *testing.T) (auditconfig.Config, string, toolchain.Catalog) {
	t.Helper()
	c, file := setup(t)
	c.Version = auditconfig.PortableVersion
	c.RulePackRoot = ""
	c.DockerScanCodeProvider = ""
	c.ToolchainCatalog = filepath.Join(filepath.Dir(file), "catalog.json")
	now := time.Now().UTC()
	binary := []byte("synthetic locally approved scanner")
	sum := sha256.Sum256(binary)
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "synthetic", ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Tools: []toolchain.CatalogTool{{Record: toolchain.Record{ID: "gitleaks", Version: "custom", SHA256: hex.EncodeToString(sum[:]), RuntimeSHA256: strings.Repeat("c", 64), RuntimeAt: now, SourceLicense: "MIT", Redistribution: "user-installed-only"}, Binary: "different-version/bin/scanner", Provider: "base"}}}
	binaryPath := filepath.Join(c.ToolchainRoot, filepath.FromSlash(catalog.Tools[0].Binary))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	writeJSONTest(t, c.ToolchainCatalog, catalog)
	writeJSONTest(t, file, c)
	raw, err := os.ReadFile(c.DockerBaseProvider)
	if err != nil {
		t.Fatal(err)
	}
	var provider runner.DockerProviderConfig
	if err := json.Unmarshal(raw, &provider); err != nil {
		t.Fatal(err)
	}
	provider.RuntimeImage = "sha256:" + catalog.Tools[0].Record.RuntimeSHA256
	writeJSONTest(t, c.DockerBaseProvider, provider)
	return c, file, catalog
}
func writeJSONTest(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPortableSecretsUsesOnlySelectedToolAndProvider(t *testing.T) {
	c, file, catalog := portableSetup(t)
	p, err := prepare(file, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.catalogTools) != 1 || p.scancodeHost.RuntimeImage != "" {
		t.Fatal("unrelated provider required")
	}
	var out, errs bytes.Buffer
	calls := 0
	executor := func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		calls++
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		if s.ToolPath != filepath.Join(c.ToolchainRoot, filepath.FromSlash(catalog.Tools[0].Binary)) || s.RuntimeDigest != "sha256:"+catalog.Tools[0].Record.RuntimeSHA256 {
			t.Fatal("legacy machine identity leaked into portable execution")
		}
		if err := h.Registry.VerifyFile("gitleaks", s.ToolPath); err != nil {
			t.Fatal(err)
		}
		args, err := runner.ManifestArguments(m, s)
		if err != nil || strings.Join(args, "\x00") != strings.Join(s.Arguments, "\x00") {
			t.Fatal("argv differs from manifest")
		}
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, Status: runner.PolicyBlocked, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.PolicyBlocked, Reason: "synthetic no host"}}, nil
	}
	code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, &confirmationInput{output: &out}, &out, &errs, executor)
	if code != 5 || calls != 1 {
		t.Fatalf("code=%d calls=%d error=%s", code, calls, errs.String())
	}
}

func TestPortableApprovalBindsCatalogAndProvider(t *testing.T) {
	for _, kind := range []string{"catalog", "provider"} {
		t.Run(kind, func(t *testing.T) {
			c, file, catalog := portableSetup(t)
			var out, errs bytes.Buffer
			var calls []string
			input := &confirmationInput{output: &out, before: func() {
				if kind == "catalog" {
					catalog.Owner = "changed owner"
					writeJSONTest(t, c.ToolchainCatalog, catalog)
				} else {
					raw, _ := os.ReadFile(c.DockerBaseProvider)
					var provider runner.DockerProviderConfig
					json.Unmarshal(raw, &provider)
					provider.RuntimeApproval.ID = "different approval"
					writeJSONTest(t, c.DockerBaseProvider, provider)
				}
			}}
			code := command(context.Background(), []string{"--config", file, "--profile", "secrets", "--execute"}, input, &out, &errs, sentinel(t, &calls))
			if code != 5 || len(calls) != 0 || !strings.Contains(errs.String(), "STALE_PREVIEW") {
				t.Fatalf("code=%d calls=%v error=%s", code, calls, errs.String())
			}
			assertNoRuns(t, c)
		})
	}
}

func TestPortableSelectedDependenciesFailClosed(t *testing.T) {
	for _, kind := range []string{"runtime mismatch", "missing selected", "license mismatch", "target overlap", "unapproved", "missing provider"} {
		t.Run(kind, func(t *testing.T) {
			c, file, catalog := portableSetup(t)
			switch kind {
			case "runtime mismatch":
				catalog.Tools[0].Record.RuntimeSHA256 = strings.Repeat("d", 64)
			case "missing selected":
				catalog.Tools[0].Record.ID = "syft"
			case "license mismatch":
				catalog.Tools[0].Record.SourceLicense = "other"
			case "target overlap":
				c.ToolchainCatalog = filepath.Join(c.Target, "catalog.json")
			case "unapproved":
				catalog.Owner = "UNAPPROVED"
			case "missing provider":
				c.DockerBaseProvider = ""
			}
			writeJSONTest(t, c.ToolchainCatalog, catalog)
			writeJSONTest(t, file, c)
			if _, err := prepare(file, "secrets"); err == nil {
				t.Fatal("accepted invalid selected dependency")
			}
			assertNoRuns(t, c)
		})
	}
}

func TestPortableCatalogExpiryNarrowsHostAuthority(t *testing.T) {
	for _, earliest := range []string{"catalog", "provider"} {
		t.Run(earliest, func(t *testing.T) {
			c, file, catalog := portableSetup(t)
			provider, err := runner.LoadDockerProviderConfig(c.DockerBaseProvider, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			want := catalog.ExpiresAt
			if earliest == "provider" {
				provider.RuntimeApproval.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)
				want = provider.RuntimeApproval.ExpiresAt
				writeJSONTest(t, c.DockerBaseProvider, provider)
			}
			p, err := prepare(file, "secrets")
			if err != nil || !p.baseHost.RuntimeApproval.ExpiresAt.Equal(want) {
				t.Fatalf("host did not retain the earliest approval expiry: %v %v", p.baseHost.RuntimeApproval.ExpiresAt, err)
			}
			// Simulate preparation before an already elapsed catalog deadline.
			// No waiting or Docker invocation is needed to exercise the real launch gate.
			beforeExpiry := time.Now().UTC().Add(-2 * time.Hour)
			catalog.ApprovedAt, catalog.ExpiresAt = beforeExpiry.Add(-time.Hour), beforeExpiry.Add(time.Hour)
			writeJSONTest(t, c.ToolchainCatalog, catalog)
			if err := p.prepareToolchain(beforeExpiry); err != nil {
				t.Fatal(err)
			}
			if !p.baseHost.RuntimeApproval.ExpiresAt.Equal(catalog.ExpiresAt) {
				t.Fatal("elapsed catalog deadline was not propagated to host")
			}
			spec, host, err := p.catalogSpec(portableSpecTemplate(t, c, "gitleaks"), p.manifests[0])
			if err != nil {
				t.Fatal(err)
			}
			result, err := host.Launch(context.Background(), spec)
			if err == nil || !strings.Contains(err.Error(), "runtime approval has expired") || len(result.RawOutput) != 0 {
				t.Fatalf("expired catalog reached a later launch stage: %#v %v", result, err)
			}
		})
	}
}

func TestPortableSkipsUnneededOSVAndWorkflowDependencies(t *testing.T) {
	for _, profile := range []string{"deep-sca", "ci-security"} {
		t.Run(profile, func(t *testing.T) {
			c, file, catalog := portableSetup(t)
			// A new empty target has neither a Go module nor workflow inputs.
			c.Target = t.TempDir()
			if profile == "deep-sca" {
				catalog = portableCatalogFixture(t, &c, []string{"syft", "grype"})
			} else {
				c.DockerBaseProvider = ""
			}
			writeJSONTest(t, c.ToolchainCatalog, catalog)
			writeJSONTest(t, file, c)
			p, err := prepare(file, profile)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := p.catalogTools["osv-scanner"]; exists {
				t.Fatal("selected-but-inapplicable OSV still required a catalog entry")
			}
			if profile == "ci-security" && (len(p.catalogTools) != 0 || p.baseHost.RuntimeImage != "") {
				t.Fatal("inapplicable workflow scan required tool or provider")
			}
			var out, errs bytes.Buffer
			var calls []string
			code := command(context.Background(), []string{"--config", file, "--profile", profile, "--execute"}, &confirmationInput{output: &out}, &out, &errs, portableSyntheticExecutor(t, c, catalog, &calls))
			want := ""
			if profile == "deep-sca" {
				want = "syft,grype"
			}
			if code != 4 || strings.Join(calls, ",") != want || !strings.Contains(out.String(), "SKIPPED_NOT_APPLICABLE") {
				t.Fatalf("unused dependency blocked execution: code=%d calls=%v error=%s", code, calls, errs.String())
			}
		})
	}
}

func TestPortableAllTenCatalogDeclarationsReachSyntheticExecutor(t *testing.T) {
	c, file, _ := portableSetup(t)
	workflow := filepath.Join(c.Target, ".github", "workflows")
	if err := os.MkdirAll(workflow, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflow, "synthetic.yml"), []byte("name: synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	catalog := portableCatalogFixture(t, &c, profiles["mvp"])
	writeJSONTest(t, c.ToolchainCatalog, catalog)
	writeJSONTest(t, file, c)
	var out, errs bytes.Buffer
	var calls []string
	code := command(context.Background(), []string{"--config", file, "--profile", "mvp", "--execute"}, &confirmationInput{output: &out}, &out, &errs, portableSyntheticExecutor(t, c, catalog, &calls))
	if code != 4 || strings.Join(calls, ",") != strings.Join(profiles["mvp"], ",") {
		t.Fatalf("portable declaration matrix failed: code=%d calls=%v error=%s", code, calls, errs.String())
	}
	runs, err := filepath.Glob(filepath.Join(c.EvidenceBase, "*", "*", "run-record.json"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("missing portable execution lineage: %v %v", runs, err)
	}
	raw, err := os.ReadFile(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	var record runner.Record
	if err := json.Unmarshal(raw, &record); err != nil || record.Validate() != nil || len(record.Executions) != 10 {
		t.Fatalf("invalid portable execution record: %#v %v", record, err)
	}
	for _, execution := range record.Executions {
		if execution.AdapterID == "sbomqs" && (execution.InputArtifact == nil || execution.InputArtifact.MediaType != "application/vnd.cyclonedx+json") {
			t.Fatal("portable SBOM quality lost its captured CycloneDX lineage")
		}
	}
}

func portableSpecTemplate(t *testing.T, c auditconfig.Config, id string) runner.ExecutionSpec {
	t.Helper()
	return runner.ExecutionSpec{
		APIVersion: "pao.dev/execution/v1alpha1", AdapterID: id, ToolID: id,
		TargetRoot: c.Target, TemporaryDir: t.TempDir(), OutputFile: id + ".json", OutputMediaType: "application/json",
		Sandbox: runner.SandboxProperties{Isolation: runner.StrongIsolation, RepositoryReadOnly: true, TemporaryWriteOnly: true, NetworkDenied: true, EnvironmentSanitized: true, ProcessTreeControlled: true, CPULimited: true, MemoryLimited: true, FilesystemIsolated: true, CleanRuntime: true},
	}
}

func portableCatalogFixture(t *testing.T, c *auditconfig.Config, ids []string) toolchain.Catalog {
	t.Helper()
	now := time.Now().UTC()
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "synthetic owner", ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	baseProvider, err := runner.LoadDockerProviderConfig(c.DockerBaseProvider, now)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	for _, id := range ids {
		m, err := adapter.LoadFile(filepath.Join(c.ManifestRoot, id, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		contents := []byte("synthetic portable tool " + id)
		item := toolchain.CatalogTool{Record: toolchain.Record{ID: id, Version: "portable-fixture", SHA256: digest(string(contents)), SourceLicense: m.SourceLicense, Redistribution: m.Redistribution, RuntimeSHA256: baseProvider.RuntimeImage[7:], RuntimeAt: now}, Binary: "portable/" + id + "/bin/scanner", Provider: "base"}
		binary := filepath.Join(c.ToolchainRoot, filepath.FromSlash(item.Binary))
		if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, contents, 0700); err != nil {
			t.Fatal(err)
		}
		if id == "grype" || id == "osv-scanner" || id == "trivy" {
			item.Database, item.Record.DatabaseSHA256, item.Record.DatabaseAt = "portable/"+id+"/database", digest(id+" database"), now
			if err := os.MkdirAll(filepath.Join(c.ToolchainRoot, filepath.FromSlash(item.Database)), 0700); err != nil {
				t.Fatal(err)
			}
			if id == "grype" {
				item.Record.DatabaseEnvironment = map[string]string{"GRYPE_DB_CACHE_DIR": "/pao/database", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
			} else if id == "osv-scanner" {
				item.Record.DatabaseEnvironment = map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/pao/database"}
			}
		}
		if id == "opengrep" || id == "scancode" || id == "reuse" {
			item.State, item.Record.StateSHA256, item.Record.StateAt = "portable/"+id+"/state", digest(id+" state"), now
			if err := os.MkdirAll(filepath.Join(c.ToolchainRoot, filepath.FromSlash(item.State)), 0700); err != nil {
				t.Fatal(err)
			}
			if id == "opengrep" {
				c.RulePackRoot = filepath.Join(filepath.Dir(c.ToolchainRoot), "rules")
				item.RulePack, item.Record.RulePackSHA256, item.Record.RulePackAt = "portable-rules", digest("rules"), now
				item.Record.StateEnvironment = map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}
				if err := os.MkdirAll(filepath.Join(c.RulePackRoot, item.RulePack), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				item.Provider = "scancode"
				item.Record.RuntimeSHA256 = strings.Repeat("d", 64)
				item.StateEntrypoint = "venv/bin/python"
				c.DockerScanCodeProvider = filepath.Join(filepath.Dir(c.DockerBaseProvider), "scancode.json")
				provider := baseProvider
				provider.RuntimeImage = "sha256:" + item.Record.RuntimeSHA256
				writeJSONTest(t, c.DockerScanCodeProvider, provider)
				if id == "scancode" {
					item.StateEntrypoint = "venv/bin/scancode"
					item.Record.LicenseDataSHA256, item.Record.LicenseDataAt = digest("licenses"), now
					item.Record.StateEnvironment = map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"}
				}
			}
		}
		catalog.Tools = append(catalog.Tools, item)
	}
	return catalog
}

func portableSyntheticExecutor(t *testing.T, c auditconfig.Config, catalog toolchain.Catalog, calls *[]string) scannerExecutor {
	t.Helper()
	byID := map[string]toolchain.CatalogTool{}
	for _, tool := range catalog.Tools {
		byID[tool.Record.ID] = tool
	}
	return func(ctx context.Context, h runner.HostRunner, s runner.ExecutionSpec, m adapter.Manifest, pd, cd, id, cap string) (runner.ToolExecution, error) {
		*calls = append(*calls, s.AdapterID)
		tool := byID[s.AdapterID]
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		if s.ToolPath != filepath.Join(c.ToolchainRoot, filepath.FromSlash(tool.Binary)) || h.Registry.VerifyFile(s.ToolID, s.ToolPath) != nil || h.Registry.VerifyRuntimeDigest(s.ToolID, s.RuntimeDigest) != nil || h.Host.(runner.DockerHost).RuntimeImage != s.RuntimeDigest {
			t.Fatal("catalog tool or provider identity was lost")
		}
		if s.DatabaseDigest != "" && h.Registry.VerifyDatabase(s.ToolID, s.DatabaseDigest, s.Environment) != nil {
			t.Fatal("catalog database approval was lost")
		}
		if s.StateDigest != "" && (h.Registry.VerifyPreparedState(s.ToolID, s.StateDigest, s.Environment) != nil || s.StateEntrypoint != tool.StateEntrypoint) {
			t.Fatal("catalog prepared state approval was lost")
		}
		if s.RulePackDigest != "" && (h.Registry.VerifyRulePackDigest(s.ToolID, s.RulePackDigest) != nil || s.RulePackPath != filepath.Join(c.RulePackRoot, filepath.FromSlash(tool.RulePack))) {
			t.Fatal("catalog rule approval was lost")
		}
		if s.LicenseDataDigest != "" && h.Registry.VerifyLicenseDataDigest(s.ToolID, s.LicenseDataDigest) != nil {
			t.Fatal("catalog license-data approval was lost")
		}
		args, err := runner.ManifestArguments(m, s)
		if err != nil || strings.Join(args, "\x00") != strings.Join(s.Arguments, "\x00") {
			t.Fatal("catalog execution diverged from fixed manifest arguments")
		}
		mediaType := s.OutputMediaType
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		raw, err := h.Artifacts.PutRaw(mediaType, []byte(fmt.Sprintf(`{"synthetic_tool":%q}`, s.ToolID)), id)
		if err != nil {
			t.Fatal(err)
		}
		artifacts := []artifact.RawArtifact{raw}
		if s.AdapterID == "syft" {
			if len(s.AdditionalOutputs) != 1 || s.AdditionalOutputs[0].MediaType != "application/vnd.cyclonedx+json" {
				t.Fatal("Syft lost declared CycloneDX output")
			}
			cdx, err := h.Artifacts.PutRaw("application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), id)
			if err != nil {
				t.Fatal(err)
			}
			// Reversed order proves Grype and sbomqs select the declared media type.
			artifacts = []artifact.RawArtifact{cdx, raw}
		}
		if s.AdapterID == "sbomqs" || s.AdapterID == "grype" {
			input, err := os.ReadFile(s.InputPath)
			if err != nil || !strings.Contains(filepath.ToSlash(s.InputPath), "/raw/sha256/") {
				t.Fatal("dependent tool did not receive captured evidence")
			}
			if (s.AdapterID == "sbomqs") != bytes.Contains(input, []byte("CycloneDX")) {
				t.Fatal("dependent tool received the wrong SBOM format")
			}
		}
		return runner.ToolExecution{ID: id, PlanDigest: pd, ManifestDigest: mustManifestDigest(t, m), AdapterID: s.AdapterID, ToolID: s.ToolID, ToolDigest: s.ToolDigest, ConfigDigest: cd, DatabaseDigest: s.DatabaseDigest, StateDigest: s.StateDigest, RuntimeDigest: s.RuntimeDigest, RulePackDigest: s.RulePackDigest, LicenseDataDigest: s.LicenseDataDigest, Status: runner.Succeeded, Sandbox: s.Sandbox, Coverage: toolchain.Coverage{ToolID: s.ToolID, Capability: cap, Status: runner.Succeeded, Reason: "synthetic no-process completion"}, RawArtifacts: artifacts}, nil
	}
}
