package baseline

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
)

func TestCompareUsesStableFindingFingerprints(t *testing.T) {
	base := FromFindings([]normalize.Finding{{StableFingerprint: "a"}, {StableFingerprint: "b"}})
	current := FromFindings([]normalize.Finding{{StableFingerprint: "b"}, {StableFingerprint: "c"}})
	diff := Compare(base, current)
	if len(diff.New) != 1 || diff.New[0] != "c" || len(diff.Resolved) != 1 || diff.Resolved[0] != "a" || len(diff.Unchanged) != 1 || diff.Unchanged[0] != "b" {
		t.Fatalf("unexpected baseline diff: %#v", diff)
	}
}
