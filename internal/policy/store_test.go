package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

const policyEvidence = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestDecisionStorePersistsCoverageAndReviewEvidenceOnce(t *testing.T) {
	store, err := OpenDecisionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := DecisionRecord{
		Policy:        Policy{ID: "policy", Version: "v1"},
		Coverage:      []toolchain.Coverage{{ToolID: "syft", Capability: "inventory", Status: "UNAVAILABLE", Reason: "fixture"}},
		AssumptionIDs: []string{"assumption-b", "assumption-a"}, VerifierEvidenceRefs: []string{policyEvidence},
		Decision: Decision{ID: "decision", PolicyDigest: policyEvidence, InputDigest: policyEvidence, DecisionDigest: policyEvidence},
	}
	path, err := store.Save(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.root, filepath.FromSlash(path))); err != nil {
		t.Fatal(err)
	}
	if second, err := store.Save(record); err != nil || second != path {
		t.Fatalf("immutable replay failed: %q %v", second, err)
	}
	record.Decision.Verdict = "PASS"
	if _, err := store.Save(record); err == nil {
		t.Fatal("same decision digest overwrote prior evidence")
	}
}
