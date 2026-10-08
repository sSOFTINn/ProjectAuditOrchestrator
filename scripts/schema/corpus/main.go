// Command corpus emits synthetic examples from the actual PAO producers for
// offline JSON Schema validation. It launches no scanner and approves no tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/policy"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/report"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

type entry struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
	Path   string `json:"path"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic schema corpus failed:", err)
		os.Exit(1)
	}
}

func run() error {
	var repo, output string
	flag.StringVar(&repo, "repo", "", "absolute PAO source directory")
	flag.StringVar(&output, "out", "", "new absolute synthetic corpus directory")
	flag.Parse()
	if !filepath.IsAbs(repo) || !filepath.IsAbs(output) {
		return fmt.Errorf("explicit absolute -repo and -out paths are required")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return fmt.Errorf("corpus destination must not already exist")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	entries := []entry{}
	writeRaw := func(name, schema string, raw []byte) error {
		path := name + ".json"
		if err := os.WriteFile(filepath.Join(output, path), raw, 0600); err != nil {
			return err
		}
		entries = append(entries, entry{Name: name, Schema: schema, Path: path})
		return nil
	}
	writeValue := func(name, schema string, value any) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return writeRaw(name, schema, raw)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	stamp := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	finding := normalize.Finding{Version: normalize.SchemaVersion, FindingID: "finding-synthetic-corpus", StableFingerprint: normalize.Fingerprint("synthetic-corpus"), Category: "vulnerability", Title: "Synthetic finding", Status: "MANUAL_REVIEW", Severity: "HIGH", Confidence: "LOW", ScannerID: "synthetic", TargetID: digest, EvidenceRefs: []string{digest}, RawResultRef: digest, ToolExecutionID: "synthetic-execution"}
	input := report.Input{Findings: []normalize.Finding{finding}, Decision: policy.Decision{ID: "synthetic-decision", Verdict: "BLOCKED", PolicyDigest: digest, InputDigest: digest, DecisionDigest: digest}, AsOf: stamp}
	for _, empty := range []bool{false, true} {
		name := "findings"
		if empty {
			name = "empty"
			input.Findings = nil
		}
		for _, renderer := range []struct {
			name, schema string
			render       func(report.Input) ([]byte, error)
		}{{"sarif", "sarif-2.1.0", report.SARIF}, {"cyclonedx", "cyclonedx-1.5", report.CycloneDX}, {"spdx", "spdx-2.3", report.SPDX}} {
			raw, err := renderer.render(input)
			if err != nil {
				return err
			}
			if err := writeRaw(renderer.name+"-"+name, renderer.schema, raw); err != nil {
				return err
			}
		}
	}
	if err := writeValue("canonical-finding", "finding-v1alpha1", finding); err != nil {
		return err
	}
	input.Findings = []normalize.Finding{finding}
	jsonl, err := report.JSONL(input)
	if err != nil {
		return err
	}
	if err := writeRaw("library-portable-finding", "portable-finding-v1", jsonl); err != nil {
		return err
	}
	manifests := []adapter.Manifest{}
	for _, id := range []string{"syft", "sbomqs", "grype", "osv-scanner", "trivy", "gitleaks", "scancode", "reuse", "opengrep", "zizmor"} {
		manifest, err := adapter.LoadFile(filepath.Join(repo, "adapters", id, "manifest.json"))
		if err != nil {
			return err
		}
		manifests = append(manifests, manifest)
		if err := writeValue("adapter-"+id, "adapter-manifest-v1alpha2", manifest); err != nil {
			return err
		}
	}
	for _, example := range []struct {
		name  string
		paths []string
	}{{"empty", nil}, {"go", []string{"go.mod", "go.sum"}}, {"python", []string{"pyproject.toml", "requirements.txt"}}, {"workflow", []string{".github/workflows/ci.yml"}}, {"mixed", []string{"go.mod", "requirements.txt", "poetry.lock", "package-lock.json", "cargo.lock", ".github/workflows/ci.yml"}}} {
		snapshot := target.Snapshot{TargetID: digest, Files: []target.FileEntry{}}
		for _, name := range example.paths {
			snapshot.Files = append(snapshot.Files, target.FileEntry{Path: name, SHA256: digest, Status: "CAPTURED"})
		}
		lock, err := plan.BuildMVPFromManifests(snapshot, true, manifests)
		if err != nil {
			return err
		}
		if err := writeValue("plan-"+example.name, "plan-v1alpha1", lock); err != nil {
			return err
		}
		configured, err := plan.BuildConfiguredFromManifests(snapshot, "mvp", digest, manifests)
		if err != nil {
			return err
		}
		if err := writeValue("configured-plan-"+example.name, "plan-v1alpha1", configured); err != nil {
			return err
		}
		// No execution records exist, so Build cannot read raw evidence or produce
		// scanner claims. Its actual whitelist renderer emits incomplete coverage.
		result := auditresult.Build("", configured, runner.Record{}, nil, true)
		if err := writeValue("public-report-"+example.name, "unified-report-v1", result.Portable()); err != nil {
			return err
		}
		if example.name == "go" {
			result.Findings = []normalize.Finding{finding}
			result.SBOMQuality = []auditresult.SBOMQualityObservation{{Score: 8.5, MissingName: 1}}
			if err := writeValue("public-report-findings", "unified-report-v1", result.Portable()); err != nil {
				return err
			}
		}
	}
	config := auditconfig.Config{Version: auditconfig.Version, Target: "/synthetic/project", EvidenceBase: "/synthetic/evidence", ReportBase: "/synthetic/reports", ToolchainRoot: "/synthetic/toolchain", RulePackRoot: "/synthetic/rules", ManifestRoot: "/synthetic/manifests", DockerBaseProvider: "/synthetic/config/base.json", DockerScanCodeProvider: "/synthetic/config/scancode.json"}
	if err := writeValue("audit-config-v1", "local-audit-config-v1", config); err != nil {
		return err
	}
	config.Version, config.ToolchainCatalog = auditconfig.PortableVersion, "/synthetic/config/catalog.json"
	if err := writeValue("audit-config-v2", "local-audit-config-v2", config); err != nil {
		return err
	}
	provider := runner.DockerProviderConfig{APIVersion: runner.DockerProviderConfigVersion, DockerPath: "/synthetic/bin/docker", DockerSHA256: digest, RuntimeImage: digest, RuntimeApproval: runner.RuntimeApproval{ID: "SYNTHETIC-NOT-APPROVAL", Owner: "synthetic-corpus", EvidenceDigest: digest, ExpiresAt: stamp.AddDate(0, 1, 0)}}
	if err := writeValue("docker-provider", "docker-provider-v1alpha1", provider); err != nil {
		return err
	}
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "SYNTHETIC-NOT-APPROVAL", ApprovedAt: stamp, ExpiresAt: stamp.AddDate(0, 1, 0), Tools: []toolchain.CatalogTool{}}
	for _, manifest := range manifests {
		tool := toolchain.CatalogTool{Binary: manifest.ID + "/bin/tool", Provider: "base", Record: toolchain.Record{ID: manifest.ID, Version: "synthetic-1", SHA256: digest, SourceLicense: manifest.SourceLicense, Redistribution: "user-installed-only", RuntimeSHA256: digest, RuntimeAt: stamp}}
		switch manifest.ID {
		case "grype", "osv-scanner", "trivy":
			tool.Database, tool.Record.DatabaseSHA256, tool.Record.DatabaseAt = manifest.ID+"/database", digest, stamp
		case "scancode", "reuse", "opengrep":
			tool.State, tool.Record.StateSHA256, tool.Record.StateAt = manifest.ID+"/state", digest, stamp
		}
		if manifest.ID == "scancode" || manifest.ID == "reuse" {
			tool.StateEntrypoint = "bin/tool"
		}
		if manifest.ID == "scancode" {
			tool.Provider, tool.Record.LicenseDataSHA256, tool.Record.LicenseDataAt = "scancode", digest, stamp
		}
		if manifest.ID == "opengrep" {
			tool.RulePack, tool.Record.RulePackSHA256, tool.Record.RulePackAt = "opengrep/rules", digest, stamp
		}
		catalog.Tools = append(catalog.Tools, tool)
	}
	// Toolchain record digests are bare SHA-256; evidence references use sha256:.
	for i := range catalog.Tools {
		r := &catalog.Tools[i].Record
		r.SHA256 = strings.TrimPrefix(r.SHA256, "sha256:")
		r.RuntimeSHA256 = strings.TrimPrefix(r.RuntimeSHA256, "sha256:")
		r.DatabaseSHA256 = strings.TrimPrefix(r.DatabaseSHA256, "sha256:")
		r.StateSHA256 = strings.TrimPrefix(r.StateSHA256, "sha256:")
		r.RulePackSHA256 = strings.TrimPrefix(r.RulePackSHA256, "sha256:")
		r.LicenseDataSHA256 = strings.TrimPrefix(r.LicenseDataSHA256, "sha256:")
	}
	if err := writeValue("toolchain-catalog", "toolchain-catalog-v1", catalog); err != nil {
		return err
	}
	// Release metadata is produced by PowerShell, not a Go library. These inert
	// examples cover both declared PAO profiles without introducing another
	// executable dependency. Validate actual package output independently with
	// --schema release-provenance-v1 --document pao-provenance.intoto.json.
	for _, hosted := range []bool{false, true} {
		name := "release-provenance-local"
		if hosted {
			name = "release-provenance-hosted"
		}
		if err := writeValue(name, "release-provenance-v1", releaseProvenanceProfile(stamp, hosted)); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(struct {
		Version string  `json:"version"`
		Entries []entry `json:"entries"`
	}{Version: "pao.dev/synthetic-schema-corpus/v1", Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "corpus.json"), raw, 0600); err != nil {
		return err
	}
	fmt.Printf("synthetic schema corpus: %d examples\n", len(entries))
	return nil
}

// releaseProvenanceProfile contains synthetic document values only; no artifact
// bytes are hashed here, no attestation is signed and no build claim is made.
func releaseProvenanceProfile(stamp time.Time, hosted bool) map[string]any {
	version := "0.2.0-rc.1"
	builderID := "https://pao.dev/release/local-metadata-generator/v1"
	metadata := map[string]any{"startedOn": stamp.Format(time.RFC3339), "finishedOn": stamp.Format(time.RFC3339)}
	if hosted {
		builderID = "https://github.com/sSOFTINn/ProjectAuditOrchestrator/.github/workflows/release.yml"
		metadata["invocationId"] = "123456789"
	}
	subjects := []map[string]any{}
	for i, name := range []string{"BUILD-METADATA.json", "pao-" + version + "-linux-amd64.tar.gz", "pao-" + version + "-windows-amd64.zip", "pao-" + version + ".cdx.json"} {
		subjects = append(subjects, map[string]any{"name": name, "digest": map[string]any{"sha256": strings.Repeat(fmt.Sprint(i+1), 64)}})
	}
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjects,
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType":          "https://pao.dev/release/v1",
				"externalParameters": map[string]any{"version": version},
				"internalParameters": map[string]any{"go_version": "go1.27.1", "source_state": "modified", "source_tree_sha256": strings.Repeat("a", 64)},
				"resolvedDependencies": []map[string]any{{
					"uri": "git+https://github.com/sSOFTINn/ProjectAuditOrchestrator", "digest": map[string]any{"gitCommit": strings.Repeat("b", 40)},
				}},
			},
			"runDetails": map[string]any{"builder": map[string]any{"id": builderID}, "metadata": metadata},
		},
	}
}
