package correlate

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
)

func TestGroupEquivalentPreservesEachSourceFinding(t *testing.T) {
	fingerprint := normalize.Fingerprint("same")
	findings := []normalize.Finding{{FindingID: "a", StableFingerprint: fingerprint}, {FindingID: "b", StableFingerprint: fingerprint}}
	grouped, groups := GroupEquivalent(findings)
	if len(grouped) != 2 || len(groups) != 1 || grouped[0].CorrelationGroupID == "" || grouped[0].CorrelationGroupID != grouped[1].CorrelationGroupID {
		t.Fatalf("correlation lost source findings or grouping: %#v %#v", grouped, groups)
	}
}
