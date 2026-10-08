package auditresult

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
)

func TestHistoricalRunProducerIsNotInventedByReportRebuild(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, nil)
	result := Build(root, lock, record, catalog, false)
	if result.RunProducer != nil || result.RunProducerStatus != "UNKNOWN_HISTORICAL" || result.ReportProducer == nil || result.ReportProducerStatus != "RECORDED" {
		t.Fatalf("historical producer invented: %#v", result)
	}
	if record.Producer != nil {
		t.Fatal("report mutated the original run")
	}
}

func TestRunAndReportProducerRemainDistinctWithoutNativeText(t *testing.T) {
	root, lock, record, catalog := syntheticRun(t, nil)
	producer, err := buildinfo.Current()
	if err != nil {
		t.Fatal(err)
	}
	producer.ExecutableSHA256 = "sha256:" + strings.Repeat("a", 64)
	record.Producer = &producer
	result := Build(root, lock, record, catalog, false)
	if result.RunProducer == nil || result.ReportProducer == nil || result.RunProducer.ExecutableSHA256 == result.ReportProducer.ExecutableSHA256 {
		t.Fatal("report rebuild erased original producer")
	}
	// Run records are data. An arbitrary Go-version string cannot use the
	// producer whitelist to inject a private path into a portable report.
	producer.GoVersion = "/private/INJECT_SECRET"
	invalid := Build(root, lock, record, catalog, false)
	if invalid.RunProducer != nil || invalid.RunProducerStatus != "INVALID" {
		t.Fatal("invalid producer admitted")
	}
	data, err := json.Marshal(invalid.Portable())
	if err != nil || strings.Contains(string(data), "INJECT_SECRET") {
		t.Fatal("producer metadata bypassed portable whitelist")
	}
}
