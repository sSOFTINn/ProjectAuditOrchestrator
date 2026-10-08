package plan

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

func TestBuildFastPlanNeverRequestsTargetWriteOrExecution(t *testing.T) {
	p := Build(target.Snapshot{TargetID: "sha256:test"}, "fast", true)
	if !p.DryRun || p.Network != "denied" || p.WritesTarget || p.ExecutesTargetCode {
		t.Fatalf("unsafe plan: %#v", p)
	}
	if len(p.RequiredCapabilities) != 9 {
		t.Fatalf("capability baseline changed: %#v", p.RequiredCapabilities)
	}
	for _, n := range p.Nodes {
		if n.WritesTarget || n.ExecutesTargetCode || n.Network != "never-during-audit" || n.Sandbox.Isolation != "container-vm" || n.ToolDigest != "UNVERIFIED" || n.ManifestDigest == "" || n.ConfigDigest == "" {
			t.Fatalf("unsafe node: %#v", n)
		}
	}
	if p.Sandbox.Isolation != "container-vm" || p.CoverageStatus != "PARTIAL" || p.PlanDigest == "" {
		t.Fatalf("plan does not declare mandatory safeguards and evidence: %#v", p)
	}
}

func TestMVPPlanHasEveryPrimaryAdapterAndConditionalSkip(t *testing.T) {
	p := Build(target.Snapshot{TargetID: "sha256:test"}, "mvp", true)
	if len(p.Nodes) != 10 {
		t.Fatalf("missing M2 adapter declarations: %#v", p.Nodes)
	}
	for _, node := range p.Nodes {
		if node.ID == "zizmor" && node.Status != "SKIPPED_NOT_APPLICABLE" {
			t.Fatalf("zizmor was not skipped without CI input: %#v", node)
		}
	}
	for _, node := range p.Nodes {
		if node.ID == "sbomqs" && (!contains(node.Inputs, "captured_cyclonedx_sbom") || node.Status == "SKIPPED_NOT_APPLICABLE") {
			t.Fatalf("sbom-quality prerequisite is not explicit: %#v", node)
		}
		if node.ID == "opengrep" || node.ID == "scancode" {
			if node.StateDigest != "UNVERIFIED" || !contains(node.Inputs, "verified_prepared_state") {
				t.Fatalf("prepared-state prerequisite is not explicit: %#v", node)
			}
		}
	}
	p = Build(target.Snapshot{TargetID: "sha256:test", Files: []target.FileEntry{{Path: ".github/workflows/ci.yml"}}}, "mvp", true)
	for _, node := range p.Nodes {
		if node.ID == "zizmor" && node.Status == "SKIPPED_NOT_APPLICABLE" {
			t.Fatalf("zizmor remained skipped with CI input: %#v", node)
		}
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestCanonicalPlanIsStableDespiteOrdering(t *testing.T) {
	first := Build(target.Snapshot{TargetID: "sha256:test"}, "fast", true)
	second := first
	second.RequiredCapabilities = append([]string(nil), first.RequiredCapabilities...)
	second.RequiredCapabilities[0], second.RequiredCapabilities[1] = second.RequiredCapabilities[1], second.RequiredCapabilities[0]
	second.Nodes[0], second.Nodes[1] = second.Nodes[1], second.Nodes[0]
	a, err := CanonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || first.PlanDigest != digest(second) {
		t.Fatalf("canonical plan changed: %s != %s", a, b)
	}
}

func TestBuildUnsupportedProfileIsExplicit(t *testing.T) {
	p := Build(target.Snapshot{TargetID: "sha256:test"}, "unknown", true)
	if len(p.Nodes) != 1 || p.Nodes[0].Status != "UNAVAILABLE" {
		t.Fatalf("expected unavailable profile node: %#v", p.Nodes)
	}
}
