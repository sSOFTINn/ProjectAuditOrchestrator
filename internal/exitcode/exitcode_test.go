package exitcode

import "testing"

func TestVerdictMappingsAreStableAndNonPassForGaps(t *testing.T) {
	if ForVerdict("PASS") != OK || ForVerdict("PASS_WITH_REVIEW") != Review || ForVerdict("INCOMPLETE") != Incomplete || ForVerdict("BLOCKED") != Blocked || ForVerdict("unknown") != Error {
		t.Fatal("unexpected exit-code mapping")
	}
}
