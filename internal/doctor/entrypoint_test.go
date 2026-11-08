package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func TestLicenseReadinessRequiresDeclaredStateEntrypoint(t *testing.T) {
	for _, entrypoint := range []string{"bin/scanner", "bin/missing", "bin", "pao-state-manifest.json"} {
		t.Run(entrypoint, func(t *testing.T) {
			path, c, d := fixture(t)
			catalog, err := toolchain.LoadCatalog(c.ToolchainCatalog, d.now())
			if err != nil {
				t.Fatal(err)
			}
			base := catalog.Tools[0]
			catalog.Tools = nil
			for _, id := range []string{"scancode", "reuse"} {
				manifestPath, err := filepath.Abs(filepath.Join("..", "..", "adapters", id, "manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := adapter.LoadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				manifestBytes, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				manifestDir := filepath.Join(c.ManifestRoot, id)
				stateRoot := filepath.Join(c.ToolchainRoot, id, "state")
				for _, dir := range []string{manifestDir, filepath.Join(stateRoot, "bin")} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				write(t, filepath.Join(manifestDir, "manifest.json"), manifestBytes)
				payload := []byte("synthetic entrypoint, never executable")
				write(t, filepath.Join(stateRoot, "bin", "scanner"), payload)
				inventory := capsuleManifest{APIVersion: "pao.dev/prepared-state/v1alpha1", AdapterID: id, Files: []capsuleEntry{{Path: "bin/scanner", SHA256: sum(payload)}}}
				raw, err := json.Marshal(inventory)
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(stateRoot, "pao-state-manifest.json"), raw)
				tool := base
				tool.Record.ID = id
				tool.Record.SourceLicense = manifest.SourceLicense
				tool.Record.Version = manifest.CompatibleToolVersions[0]
				tool.Record.StateSHA256 = sum(raw)
				tool.Record.StateAt = d.now().Add(-time.Hour)
				tool.State = id + "/state"
				tool.StateEntrypoint = "bin/scanner"
				if id == "scancode" {
					tool.Record.LicenseDataSHA256 = sum(payload)
					tool.Record.LicenseDataAt = d.now().Add(-time.Hour)
				} else {
					tool.StateEntrypoint = entrypoint
				}
				catalog.Tools = append(catalog.Tools, tool)
			}
			jsonFile(t, c.ToolchainCatalog, catalog)
			result := inspect(context.Background(), path, "license", d)
			want := "SETUP_REQUIRED"
			if entrypoint == "bin/scanner" {
				want = "READY"
			}
			found := false
			for _, check := range result.Checks {
				if check.ID == "tool.reuse.entrypoint" {
					found = true
					if check.Status != want {
						t.Fatalf("entrypoint %q: want %s, got %+v", entrypoint, want, check)
					}
				}
			}
			if !found || result.Status != want {
				t.Fatalf("entrypoint %q: expected %s with a separate entrypoint check, got %+v", entrypoint, want, result)
			}
		})
	}
}
