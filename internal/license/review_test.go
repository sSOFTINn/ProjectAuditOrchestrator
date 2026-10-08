package license

import "testing"

const licenseEvidence = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAmbiguousLicenseExpressionsEnterManualReview(t *testing.T) {
	observations := []Observation{
		{ComponentID: "noassertion", SPDXExpression: "NOASSERTION", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
		{ComponentID: "custom", SPDXExpression: "LicenseRef-Company", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
		{ComponentID: "unknown", SPDXExpression: "MadeUp-1.0", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
		{ComponentID: "dual", SPDXExpression: "MIT OR Apache-2.0", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
	}
	queue, err := Queue(observations)
	if err != nil || len(queue) != len(observations) {
		t.Fatalf("ambiguous licenses escaped review: %#v %v", queue, err)
	}
	for _, item := range queue {
		if item.Status != StatusManualReview || item.SPDXExpression == "" || len(item.Reasons) == 0 {
			t.Fatalf("invalid manual-review item: %#v", item)
		}
	}
}

func TestKnownLicenseAndDocumentedElectionDoNotAutoQueue(t *testing.T) {
	observations := []Observation{
		{ComponentID: "single", SPDXExpression: "MIT", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
		{ComponentID: "dual-with-evidence", SPDXExpression: "MIT OR Apache-2.0", SelectedExpression: "MIT", SelectionBasis: "component NOTICE permits MIT election; reviewed by license steward", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved},
	}
	queue, err := Queue(observations)
	if err != nil || len(queue) != 0 {
		t.Fatalf("documented expression unexpectedly queued: %#v %v", queue, err)
	}
}

func TestLicenseElectionCannotLackDocumentedBasis(t *testing.T) {
	observation := Observation{ComponentID: "dual", SPDXExpression: "MIT OR Apache-2.0", SelectedExpression: "MIT", EvidenceRefs: []string{licenseEvidence}, Status: StatusObserved}
	if _, err := Queue([]Observation{observation}); err == nil {
		t.Fatal("unexplained license election was accepted")
	}
}
