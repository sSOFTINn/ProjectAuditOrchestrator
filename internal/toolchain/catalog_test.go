package toolchain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogStrictOwnerApproval(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c := Catalog{APIVersion: CatalogVersion, Owner: "synthetic owner", ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Tools: []CatalogTool{{Record: Record{ID: "gitleaks", Version: "test", SHA256: strings.Repeat("a", 64), SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: strings.Repeat("b", 64), RuntimeAt: now}, Binary: "gitleaks/custom/bin/scanner", Provider: "base"}}}
	data, _ := json.Marshal(c)
	file := filepath.Join(t.TempDir(), "catalog.json")
	check := func(data []byte) error {
		t.Helper()
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCatalog(file, now)
		return err
	}
	if err := check(data); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Catalog){
		"unapproved":        func(c *Catalog) { c.Owner = "UNAPPROVED" },
		"padded unapproved": func(c *Catalog) { c.Owner = " UNAPPROVED " },
		"future":            func(c *Catalog) { c.ApprovedAt = now.Add(time.Minute) },
		"expired":           func(c *Catalog) { c.ExpiresAt = now },
		"long lifetime":     func(c *Catalog) { c.ExpiresAt = now.Add(91 * 24 * time.Hour) },
		"empty":             func(c *Catalog) { c.Tools = []CatalogTool{} },
		"duplicate tool":    func(c *Catalog) { c.Tools = append(c.Tools, c.Tools[0]) },
		"escape":            func(c *Catalog) { c.Tools[0].Binary = "../escape" },
		"absolute":          func(c *Catalog) { c.Tools[0].Binary = "/bin/tool" },
		"bad provider":      func(c *Catalog) { c.Tools[0].Provider = "remote" },
		"missing runtime":   func(c *Catalog) { c.Tools[0].Record.RuntimeSHA256 = "" },
		"missing database":  func(c *Catalog) { c.Tools[0].Record.ID = "trivy" },
		"unpaired digest":   func(c *Catalog) { c.Tools[0].Record.DatabaseSHA256 = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var bad Catalog
			json.Unmarshal(data, &bad)
			mutate(&bad)
			raw, _ := json.Marshal(bad)
			if check(raw) == nil {
				t.Fatal("accepted invalid catalog")
			}
		})
	}
	for name, bad := range map[string]string{
		"duplicate":         strings.Replace(string(data), `"owner":`, `"owner":"first","owner":`, 1),
		"escaped duplicate": strings.Replace(string(data), `"owner":`, `"\u006fwner":"first","owner":`, 1),
		"case alias":        strings.Replace(string(data), `"runtime_at":`, `"Runtime_at":`, 1),
		"unknown":           strings.Replace(string(data), `"binary":`, `"arguments":["sh"],"binary":`, 1),
		"nested duplicate":  strings.Replace(string(data), `"id":`, `"id":"syft","id":`, 1),
		"null":              strings.Replace(string(data), `"tools":[`, `"tools":null,"unused":[`, 1),
		"trailing":          string(data) + "{}",
		"size":              strings.Repeat(" ", catalogLimit) + string(data),
	} {
		t.Run(name, func(t *testing.T) {
			if check([]byte(bad)) == nil {
				t.Fatal("accepted ambiguous JSON")
			}
		})
	}
}

func TestCatalogApprovalErrorsIdentifyFieldsWithoutPrivateValues(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	const privateValue = "synthetic-owner-do-not-print"
	base := Catalog{
		APIVersion: CatalogVersion, Owner: privateValue, ApprovedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		Tools: []CatalogTool{{Record: Record{ID: "gitleaks", Version: "test", SHA256: strings.Repeat("a", 64), SourceLicense: "MIT", Redistribution: "user-installed-only", RuntimeSHA256: strings.Repeat("b", 64), RuntimeAt: now}, Binary: "gitleaks/custom/bin/scanner", Provider: "base"}},
	}
	for _, tc := range []struct {
		name, field string
		mutate      func(*Catalog)
	}{
		{"version", "api_version", func(c *Catalog) { c.APIVersion = privateValue }},
		{"unapproved", "owner", func(c *Catalog) { c.Owner = " UNAPPROVED " }},
		{"owner-control", "owner", func(c *Catalog) { c.Owner = privateValue + "\n" }},
		{"future", "approved_at", func(c *Catalog) { c.ApprovedAt = now.Add(time.Hour) }},
		{"missing-time", "approved_at", func(c *Catalog) { c.ApprovedAt = time.Time{} }},
		{"expired", "expires_at", func(c *Catalog) { c.ExpiresAt = now }},
		{"too-long", "expires_at", func(c *Catalog) { c.ExpiresAt = now.Add(91 * 24 * time.Hour) }},
		{"no-tools", "tools", func(c *Catalog) { c.Tools = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			tc.mutate(&bad)
			// Keep the empty tool list a JSON array so strict JSON accepts its type
			// and the approval validator can explain which field needs review.
			if bad.Tools == nil {
				bad.Tools = []CatalogTool{}
			}
			raw, _ := json.Marshal(bad)
			file := filepath.Join(t.TempDir(), "catalog.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalog(file, now)
			if err == nil || !strings.Contains(err.Error(), `"`+tc.field+`"`) || strings.Contains(err.Error(), privateValue) {
				t.Fatalf("expected actionable value-free rejection for %s, got %v", tc.field, err)
			}
		})
	}
}
