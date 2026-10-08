package license_test

import (
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/adapters/reuse"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/adapters/scancode"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/license"
)

const adapterEvidence = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestLicenseAdaptersPreserveExactExpressionsForManualReview(t *testing.T) {
	scancodeObservations, err := scancode.ParseObservations([]byte(`{"files":[{"path":"a.txt","detected_license_expression":"LicenseRef-Company"}]}`), adapterEvidence)
	if err != nil {
		t.Fatal(err)
	}
	reuseObservations, err := reuse.ParseObservations([]byte(`{"licenses":[{"path":"b.txt","spdx_expression":"MIT OR Apache-2.0"}]}`), adapterEvidence)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := license.Queue(append(scancodeObservations, reuseObservations...))
	if err != nil || len(queue) != 2 || queue[0].SPDXExpression != "LicenseRef-Company" || queue[1].SPDXExpression != "MIT OR Apache-2.0" {
		t.Fatalf("adapter ambiguity was not preserved: %#v %v", queue, err)
	}
}
