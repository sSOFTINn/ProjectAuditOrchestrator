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
