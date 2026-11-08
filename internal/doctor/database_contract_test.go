package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func TestGrypePreparedMetadataAcceptsPinnedRemoteFilename(t *testing.T) {
	root := t.TempDir()
	payload := []byte("synthetic offline Grype database")
	write(t, filepath.Join(root, "vulnerability.db"), payload)
	raw := []byte(`{"schema":"pao.dev/toolchain-database-metadata/v1","tool":"grype","files":[{"path":"vulnerability.db","sha256":"` + sum(payload) + `"}],"built_at":"2026-11-07T10:00:00Z","source":{"version":"pao.dev/database-download-lock/v1","tool":"grype","url":"https://grype.anchore.io/databases/v6/synthetic-db.tar.zst","sha256":"` + strings.Repeat("a", 64) + `","bytes":100,"filename":"grype-db.tar.zst","remote_filename":"synthetic-db.tar.zst","format":"tar.zst","at":"2026-11-07T10:00:00Z","resolved_at":"2026-11-07T11:00:00Z","metadata_sha256":"` + strings.Repeat("b", 64) + `"},"archive_sha256":"` + strings.Repeat("a", 64) + `"}`)
	write(t, filepath.Join(root, "metadata.json"), raw)
	if err := verifyCapsule(context.Background(), root, "database", "sha256:"+sum(raw), "grype"); err != nil {
		t.Fatalf("setup-produced Grype provenance rejected: %v", err)
	}
	write(t, filepath.Join(root, "vulnerability.db"), []byte("altered"))
	if err := verifyCapsule(context.Background(), root, "database", "sha256:"+sum(raw), "grype"); err == nil {
		t.Fatal("provenance bypassed database byte verification")
	}
}

func TestDoctorRejectsGrypeDaySixDatabase(t *testing.T) {
	path, c, d := fixture(t)
	raw, err := os.ReadFile(c.ToolchainCatalog)
	if err != nil {
		t.Fatal(err)
	}
	var catalog toolchain.Catalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	tool := &catalog.Tools[0]
	tool.Record.ID, tool.Record.Version, tool.Record.SourceLicense = "grype", "0.118.0", "Apache-2.0"
	tool.Record.DatabaseSHA256, tool.Database = strings.Repeat("c", 64), "synthetic-database"
	if err := os.Mkdir(filepath.Join(c.ManifestRoot, "grype"), 0700); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join("..", "..", "adapters", "grype", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(c.ManifestRoot, "grype", "manifest.json"), manifest)
	for _, days := range []int{4, 6} {
		tool.Record.DatabaseAt = d.now().Add(-time.Duration(days) * 24 * time.Hour)
		jsonFile(t, c.ToolchainCatalog, catalog)
		result := inspect(context.Background(), path, "deep-sca", d)
		found := false
		for _, check := range result.Checks {
			if check.ID != "tool.grype.freshness" {
				continue
			}
			found = true
			if (check.Status == "READY") != (days == 4) || (days == 6 && !strings.Contains(check.Reason, toolchain.ReasonDatabaseStale)) {
				t.Fatalf("Grype day %d freshness mismatch: %+v", days, check)
			}
		}
		if !found {
			t.Fatalf("Grype freshness check missing: %+v", result)
		}
	}
}
