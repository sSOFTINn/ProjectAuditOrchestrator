package plan

import (
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestMVPPlanUsesFileBackedManifests(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "adapters"))
	if err != nil {
		t.Fatal(err)
	}
	manifests := make([]adapter.Manifest, 0, 10)
	for _, id := range []string{"syft", "sbomqs", "grype", "osv-scanner", "scancode", "reuse", "trivy", "gitleaks", "opengrep", "zizmor"} {
		manifest, err := adapter.LoadFile(filepath.Join(root, id, "manifest.json"))
		if err != nil {
			t.Fatalf("load %s: %v", id, err)
		}
		manifests = append(manifests, manifest)
	}
	plan, err := BuildMVPFromManifests(target.Snapshot{TargetID: "sha256:target"}, true, manifests)
	if err != nil || len(plan.Nodes) != len(manifests) {
		t.Fatalf("manifest-backed M2 plan failed: %#v %v", plan.Nodes, err)
	}
	for _, node := range plan.Nodes {
		if node.ID == "trivy" && node.Capability != "vulnerability" {
			t.Fatalf("Trivy declared coverage beyond the configured vulnerability scan: %#v", node)
		}
		if node.ID == "sbomqs" && (!contains(node.Inputs, "captured_cyclonedx_sbom") || node.Status == "SKIPPED_NOT_APPLICABLE") {
			t.Fatalf("sbomqs did not require captured CycloneDX evidence: %#v", node)
		}
		if node.ManifestDigest == "" {
			t.Fatalf("manifest digest missing from node: %#v", node)
		}
		if node.ID == "zizmor" && node.Status != "SKIPPED_NOT_APPLICABLE" {
			t.Fatalf("conditional adapter not skipped: %#v", node)
		}
		if node.ID == "osv-scanner" && node.Status != "SKIPPED_NOT_APPLICABLE" {
			t.Fatalf("OSV Scanner was not skipped without a Go module input: %#v", node)
		}
		if node.ID == "opengrep" || node.ID == "scancode" {
			if node.StateDigest != "UNVERIFIED" || !contains(node.Inputs, "verified_prepared_state") {
				t.Fatalf("manifest plan omits prepared-state prerequisite: %#v", node)
			}
			if node.RuntimeDigest != "UNVERIFIED" || !contains(node.Inputs, "verified_runtime") {
				t.Fatalf("manifest plan omits runtime prerequisite: %#v", node)
			}
		}
		if node.ID == "opengrep" && (node.RulePackDigest != "UNVERIFIED" || !contains(node.Inputs, "verified_rule_pack")) {
			t.Fatalf("Opengrep plan omits rule-pack prerequisite: %#v", node)
		}
		if node.ID == "scancode" && (node.LicenseDataDigest != "UNVERIFIED" || !contains(node.Inputs, "verified_license_data")) {
			t.Fatalf("ScanCode plan omits license-data prerequisite: %#v", node)
		}
	}
	withGo, err := BuildMVPFromManifests(target.Snapshot{TargetID: "sha256:target", Files: []target.FileEntry{{Path: "go.mod"}}}, true, manifests)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range withGo.Nodes {
		if node.ID == "osv-scanner" && node.Status == "SKIPPED_NOT_APPLICABLE" {
			t.Fatalf("OSV Scanner remained skipped with a Go module input: %#v", node)
		}
	}
}

func TestBuiltinTrivyCoverageMatchesFilesystemVulnerabilityScan(t *testing.T) {
	for _, profile := range []string{"fast", "mvp"} {
		p := Build(target.Snapshot{TargetID: "sha256:target"}, profile, true)
		found := false
		for _, node := range p.Nodes {
			if node.ID == "trivy" {
				found = true
				if node.Capability != "vulnerability" {
					t.Fatalf("%s plan overstates Trivy coverage: %#v", profile, node)
				}
			}
		}
		if !found {
			t.Fatalf("%s plan lost the Trivy node", profile)
		}
	}
}

func TestOSVInputPresenceAndAdmittedFeedCoverageAreDistinct(t *testing.T) {
	manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", "osv-scanner", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, applicability, support, status string
		paths                                []string
		reasons                              []string
	}{
		{"go-only", "APPLICABLE", "SUPPORTED", "PREFLIGHT_REQUIRED", []string{"go.mod", "go.sum"}, nil},
		{"python-only", "APPLICABLE", "UNSUPPORTED", "UNSUPPORTED", []string{"pyproject.toml", "requirements.txt"}, []string{"DB_ECOSYSTEM_UNSUPPORTED"}},
		{"no-dependencies", "NOT_APPLICABLE", "NOT_APPLICABLE", "SKIPPED_NOT_APPLICABLE", []string{"README.md"}, nil},
		{"workflow-only", "NOT_APPLICABLE", "NOT_APPLICABLE", "SKIPPED_NOT_APPLICABLE", []string{".github/workflows/ci.yml"}, nil},
		{"mixed", "APPLICABLE", "PARTIAL", "PREFLIGHT_REQUIRED", []string{"go.mod", "pyproject.toml"}, []string{"DB_ECOSYSTEM_UNSUPPORTED"}},
		{"python-custom-locks", "APPLICABLE", "UNSUPPORTED", "UNSUPPORTED", []string{"requirements.lock", "build-requirements.lock"}, []string{"DB_ECOSYSTEM_UNSUPPORTED", "UNSUPPORTED_INPUT_FORMAT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := target.Snapshot{TargetID: "sha256:target"}
			for _, path := range tc.paths {
				s.Files = append(s.Files, target.FileEntry{Path: path})
			}
			p, err := BuildConfiguredFromManifests(s, "mvp", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []adapter.Manifest{manifest})
			if err != nil {
				t.Fatal(err)
			}
			n := p.Nodes[0]
			if n.Applicability != tc.applicability || n.SupportStatus != tc.support || n.Status != tc.status || len(n.SupportReasons) != len(tc.reasons) {
				t.Fatalf("wrong distinction: %+v", n)
			}
			for _, code := range tc.reasons {
				if !contains(n.SupportReasons, code) {
					t.Fatalf("reason %s missing: %+v", code, n)
				}
			}
			if !contains(n.Limitations, "local-database-currently-covers-go-only") || !contains(n.Limitations, "no-remediation-or-package-manager-execution") {
				t.Fatalf("manifest limitations lost: %+v", n)
			}
			if n.Status == "UNSUPPORTED" && len(n.Command) != 0 {
				t.Fatal("unsupported input retained executable command")
			}
		})
	}
}

func TestInventoryPreviewPreservesUnsupportedCustomFormat(t *testing.T) {
	manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", "syft", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adapter.LoadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildMVPFromManifests(target.Snapshot{TargetID: "sha256:target", Files: []target.FileEntry{{Path: "requirements.lock"}, {Path: "build-requirements.lock"}}}, true, []adapter.Manifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	n := p.Nodes[0]
	if n.Applicability != "APPLICABLE" || n.SupportStatus != "PARTIAL" || !contains(n.SupportReasons, "UNSUPPORTED_INPUT_FORMAT") || !contains(n.Limitations, "does-not-assess-vulnerabilities") || n.Status == "SKIPPED_NOT_APPLICABLE" {
		t.Fatalf("inventory preview hides an existing input: %+v", n)
	}
}
