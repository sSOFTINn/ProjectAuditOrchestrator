package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOwnerApprovedToolRequiresExactFreshIdentity(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "approved-tool.json")
	valid := `{"api_version":"pao.dev/owner-tool-record/v1","id":"sbomqs","version":"1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_license":"Apache-2.0","redistribution":"user-installed-only","binary":"bin/sbomqs","platform":"linux-amd64","owner":"sSOFTINn","approved_at":"2026-09-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	tool, err := LoadOwnerApprovedTool(path, "sbomqs", now)
	if err != nil || tool.Record.ID != "sbomqs" || tool.Binary != "bin/sbomqs" || tool.MetadataDigest == "" {
		t.Fatalf("valid owner tool rejected: %#v %v", tool, err)
	}
	for name, bad := range map[string]string{
		"duplicate": strings.Replace(valid, `"version":`, `"version":"other","version":`, 1),
		"traversal": strings.Replace(valid, `"bin/sbomqs"`, `"../sbomqs"`, 1),
		"parent":    strings.Replace(valid, `"bin/sbomqs"`, `".."`, 1),
		"drive":     strings.Replace(valid, `"bin/sbomqs"`, `"C:/sbomqs"`, 1),
		"oversized": valid + strings.Repeat(" ", maxOwnerToolRecordBytes),
		"platform":  strings.Replace(valid, `"linux-amd64"`, `"windows-amd64"`, 1),
		"stale":     strings.Replace(valid, `"2026-09-01T00:00:00Z"`, `"2026-01-01T00:00:00Z"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOwnerApprovedTool(path, "sbomqs", now); err == nil {
				t.Fatal("unsafe tool record accepted")
			}
		})
	}
}
