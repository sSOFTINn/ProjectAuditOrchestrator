package osvscanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeFixtureStatusMatrix(t *testing.T) {
	cases := map[string]string{"success.json": "SUCCEEDED", "empty.json": "NO_FINDINGS", "partial.json": "PARTIAL", "error.json": "FAILED", "malformed.json": "FAILED"}
	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scanner-outputs", "osv-scanner", name))
			if err != nil {
				t.Fatal(err)
			}
			if result := Parse(raw); result.Status != expected {
				t.Fatalf("fixture status: %#v", result)
			}
		})
	}
}
