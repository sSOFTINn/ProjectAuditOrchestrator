package sbomqs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFailsExplicitly(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{`{"files":[{"avg_score":8.5}]}`, "SUCCEEDED"}, {`{"run_id":"synthetic","timestamp":"2026-09-06T00:00:00Z","creation_info":{},"files":[{"file_name":"sample.cdx.json","spec":"CycloneDX","spec_version":"1.5","file_format":"json","avg_score":8.5,"num_components":1,"creation_time":"2026-09-06T00:00:00Z","gen_tool_name":"synthetic","gen_tool_version":"1","scores":[]}]}`, "SUCCEEDED"}, {`{`, "FAILED"}, {`{"files":[{"avg_score":11}]}`, "PARTIAL"}, {`{"error":"bad input"}`, "FAILED"}, {`{"score":8.5,"score":9}`, "FAILED"}, {`{"files":[{"avg_score":"8.5"}]}`, "FAILED"}, {`{"files":[{"avg_score":8.5,"avg_score":9}]}`, "FAILED"}, {`{"files":[{"avg_score":8.5}],"note":"untrusted"}`, "FAILED"}, {`{"run_id":"synthetic","timestamp":"2026-09-06T00:00:00Z","creation_info":{},"files":[{"sbom_quality_score":8.5}]}`, "PARTIAL"}, {`{"run_id":1,"files":[{"avg_score":8.5}]}`, "FAILED"}} {
		if got := Parse([]byte(tc.raw)); got.Status != tc.want {
			t.Fatalf("Parse(%s) = %#v, want %s", tc.raw, got, tc.want)
		}
	}
}

func TestParseContractFixtures(t *testing.T) {
	for _, tc := range []struct{ file, want string }{{"success.json", "SUCCEEDED"}, {"duplicate-score.json", "FAILED"}, {"malformed.json", "FAILED"}} {
		raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
		if err != nil || Parse(raw).Status != tc.want {
			t.Fatalf("%s: %v %#v", tc.file, err, Parse(raw))
		}
	}
	if got := Parse(bytes.Repeat([]byte(" "), maxOutputBytes+1)); got.Status != "FAILED" {
		t.Fatalf("oversize = %#v", got)
	}
}
