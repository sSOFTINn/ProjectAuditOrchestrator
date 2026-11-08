package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func TestOSVPreparedLayoutMatchesPinnedReadOnlyCache(t *testing.T) {
	d, calls := testDatabaseDownloader(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	base := t.TempDir()
	cache, tools := filepath.Join(base, "cache"), filepath.Join(base, "tools")
	for _, path := range []string{cache, tools} {
		if err := privateTree(path); err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := prepareDatabase(context.Background(), d, cache, tools, "osv-scanner", nil)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tools, filepath.FromSlash(prepared.Path))
	// OSV-Scanner 2.5.1's pinned scalibr matcher appends this namespace to
	// OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, including in offline mode.
	archive, err := os.ReadFile(filepath.Join(root, "osv-scalibr", "Go", "all.zip"))
	if err != nil {
		t.Fatalf("pinned offline matcher cannot read its prepared cache: %v", err)
	}
	var metadata preparedDatabaseMetadata
	raw, err := os.ReadFile(filepath.Join(root, "metadata.json"))
	if err != nil || json.Unmarshal(raw, &metadata) != nil {
		t.Fatal("prepared metadata unavailable")
	}
	if len(metadata.Files) != 1 || metadata.Files[0].Path != "osv-scalibr/Go/all.zip" || metadata.Files[0].SHA256 != hashBytes(archive) || metadata.ArchiveSHA256 != hashBytes(archive) {
		t.Fatal("prepared cache must retain the exact locked archive under the native namespace")
	}
	before := *calls
	resumed, err := prepareDatabase(context.Background(), d, cache, tools, "osv-scanner", nil)
	if err != nil || !reflect.DeepEqual(resumed, prepared) || *calls != before {
		t.Fatalf("valid sealed namespace did not resume offline: %v", err)
	}
}

// modelLegacyOSVLayout models an intact, correctly hashed completion made by
// the previous setup implementation. Only this test's synthetic files change.
func modelLegacyOSVLayout(t *testing.T, tools string, prepared databasePrepared) databasePrepared {
	t.Helper()
	root := filepath.Join(tools, filepath.FromSlash(prepared.Path))
	metadataPath := filepath.Join(root, "metadata.json")
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata preparedDatabaseMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil || len(metadata.Files) != 1 {
		t.Fatal("unexpected synthetic metadata")
	}
	const legacy = "osv-scanner/Go/all.zip"
	if metadata.Files[0].Path != legacy {
		destination := filepath.Join(root, filepath.FromSlash(legacy))
		if err := privateTree(filepath.Dir(destination)); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(root, filepath.FromSlash(metadata.Files[0].Path)), destination); err != nil {
			t.Fatal(err)
		}
		metadata.Files[0].Path = legacy
	}
	raw, err = json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	prepared.Digest = prefix(hashBytes(raw))
	ready, err := json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "database-preparation", "osv-scanner-ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestOSVResumeRejectsLegacyNamespaceWithoutMutation(t *testing.T) {
	d, calls := testDatabaseDownloader(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	base := t.TempDir()
	cache, tools := filepath.Join(base, "cache"), filepath.Join(base, "tools")
	for _, path := range []string{cache, tools} {
		if err := privateTree(path); err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := prepareDatabase(context.Background(), d, cache, tools, "osv-scanner", nil)
	if err != nil {
		t.Fatal(err)
	}
	modelLegacyOSVLayout(t, tools, prepared)
	before, err := inventory(base, "")
	if err != nil {
		t.Fatal(err)
	}
	requests := *calls
	_, err = prepareDatabase(context.Background(), d, cache, tools, "osv-scanner", nil)
	if err == nil || !strings.Contains(err.Error(), "layout") || !strings.Contains(err.Error(), "fresh") {
		t.Fatalf("intact legacy cache must require fresh preparation, got %v", err)
	}
	after, err := inventory(base, "")
	if err != nil || !reflect.DeepEqual(before, after) || *calls != requests {
		t.Fatal("rejected legacy cache, marker or locked download changed")
	}
}

func TestLoadPreparedRejectsLegacyOSVLayout(t *testing.T) {
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	d, _ := testDatabaseDownloader(t, stamp)
	base := t.TempDir()
	binary := []byte("synthetic OSV executable; never invoked")
	runtime := strings.Repeat("a", 64)
	p := Plan{Root: base, Digest: prefix(strings.Repeat("b", 64)), Tools: []ToolRecipe{{ID: "osv-scanner", Version: "2.5.1", BinarySHA256: hashBytes(binary), License: "Apache-2.0"}}}
	gen := generation(p)
	tools := filepath.Join(gen, "tools")
	for _, path := range []string{filepath.Join(base, "cache"), tools} {
		if err := privateTree(path); err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := prepareDatabase(context.Background(), d, filepath.Join(base, "cache"), tools, "osv-scanner", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOnce(filepath.Join(tools, "osv"), binary); err != nil {
		t.Fatal(err)
	}
	v := preparedInstallation{Version: "pao.dev/prepared-installation/v1", PlanDigest: p.Digest, Generation: gen, State: filepath.Join(base, "state"), Runtime: prefix(runtime), Tools: []toolchain.CatalogTool{{Binary: "osv", Database: prepared.Path, Record: toolchain.Record{ID: "osv-scanner", Version: "2.5.1", SHA256: hashBytes(binary), SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", DatabaseSHA256: strings.TrimPrefix(prepared.Digest, "sha256:"), DatabaseAt: stamp, RuntimeSHA256: runtime, RuntimeAt: stamp}}}}
	if err := privateTree(filepath.Join(gen, "records")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(gen, "records", "prepared.json")
	raw, _ := json.Marshal(v)
	if err := writeOnce(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrepared(p); err != nil {
		t.Fatalf("valid native layout rejected: %v", err)
	}
	legacy := modelLegacyOSVLayout(t, tools, prepared)
	v.Tools[0].Record.DatabaseSHA256 = strings.TrimPrefix(legacy.Digest, "sha256:")
	raw, _ = json.Marshal(v)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrepared(p); err == nil || !strings.Contains(err.Error(), "layout") {
		t.Fatalf("verification-only path accepted legacy database: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("verification changed prepared identity")
	}
}
