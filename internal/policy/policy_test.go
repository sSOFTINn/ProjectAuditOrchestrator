package policy

import (
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func fixtureFinding(severity, status string) normalize.Finding {
	return normalize.Finding{Version: normalize.SchemaVersion, FindingID: "finding-1", StableFingerprint: normalize.Fingerprint("fixture"), Category: "vulnerability", Title: "fixture", Status: status, Severity: severity, Confidence: "HIGH", ScannerID: "fixture", TargetID: "sha256:fixture", EvidenceRefs: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, RawResultRef: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ToolExecutionID: "exec-1"}
}

func TestPolicyNeverPassesIncompleteCoverage(t *testing.T) {
	p := Policy{ID: "default", Version: "1", BlockAtOrAbove: "HIGH", RequireCompleteCoverage: true}
	decision, err := p.Evaluate([]normalize.Finding{fixtureFinding("INFO", "OPEN")}, []toolchain.Coverage{{ToolID: "syft", Capability: "inventory", Status: "UNAVAILABLE"}}, nil, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	if err != nil || decision.Verdict != "INCOMPLETE" || decision.PolicyDigest == "" || decision.InputDigest == "" || decision.DecisionDigest == "" {
		t.Fatalf("unexpected incomplete decision: %#v %v", decision, err)
	}
}

func TestUnknownSeverityRequiresReviewEvenWhenStatusIsOpen(t *testing.T) {
	p := Policy{ID: "default", Version: "1", BlockAtOrAbove: "HIGH"}
	d, err := p.Evaluate([]normalize.Finding{fixtureFinding("UNKNOWN", "OPEN")}, []toolchain.Coverage{{Status: "SUCCEEDED"}}, nil, time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC))
	if err != nil || d.Verdict != "PASS_WITH_REVIEW" {
		t.Fatalf("unknown became clean: %#v %v", d, err)
	}
}

func TestPolicyRequiresValidReviewedWaiver(t *testing.T) {
	p := Policy{ID: "default", Version: "1", BlockAtOrAbove: "HIGH"}
	asOf := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	decision, err := p.Evaluate([]normalize.Finding{fixtureFinding("HIGH", "OPEN")}, []toolchain.Coverage{{Status: "SUCCEEDED"}}, nil, asOf)
	if err != nil || decision.Verdict != "BLOCKED" {
		t.Fatalf("high finding was not blocked: %#v %v", decision, err)
	}
	waiver := &Waiver{ID: "waiver-1", Owner: "owner", Reason: "synthetic", Scope: "finding:finding-1", CreatedAt: asOf.Add(-time.Hour), ExpiresAt: asOf.Add(time.Hour), ReviewID: "review-1"}
	decision, err = p.Evaluate([]normalize.Finding{fixtureFinding("HIGH", "OPEN")}, []toolchain.Coverage{{Status: "SUCCEEDED"}}, waiver, asOf)
	if err != nil || decision.Verdict != "PASS_WITH_REVIEW" || decision.WaiverID != waiver.ID {
		t.Fatalf("reviewed waiver was not recorded: %#v %v", decision, err)
	}
}

func TestPolicyRejectsWaiverOutsideFindingScope(t *testing.T) {
	p := Policy{ID: "default", Version: "1", BlockAtOrAbove: "HIGH"}
	asOf := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	waiver := &Waiver{ID: "waiver-1", Owner: "owner", Reason: "synthetic", Scope: "finding:other-finding", CreatedAt: asOf.Add(-time.Hour), ExpiresAt: asOf.Add(time.Hour), ReviewID: "review-1"}
	decision, err := p.Evaluate([]normalize.Finding{fixtureFinding("CRITICAL", "OPEN")}, []toolchain.Coverage{{Status: "SUCCEEDED"}}, waiver, asOf)
	if err != nil || decision.Verdict != "BLOCKED" || decision.WaiverID != "" {
		t.Fatalf("out-of-scope waiver bypassed policy: %#v %v", decision, err)
	}
}
