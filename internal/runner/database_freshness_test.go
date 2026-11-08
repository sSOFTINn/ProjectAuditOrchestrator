package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func TestGrypeDaySixDatabaseIsBlockedBeforeHostInvocation(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for _, days := range []int{4, 6} {
		spec, _, store := verifiedFixture(t)
		spec.AdapterID, spec.ToolID = "grype", "grype"
		spec.DatabasePath, _ = syntheticFreshnessDatabase(t)
		metadataPath := filepath.Join(spec.DatabasePath, databaseMetadataName)
		raw, err := os.ReadFile(metadataPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), `"tool":"fixture"`, `"tool":"grype"`, 1))
		if err := os.WriteFile(metadataPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		spec.DatabaseDigest = "sha256:" + hex.EncodeToString(sum[:])
		registry, err := toolchain.New([]toolchain.Record{{ID: "grype", Version: "synthetic", SHA256: strings.TrimPrefix(spec.ToolDigest, "sha256:"), SourceLicense: "Apache-2.0", Redistribution: "user-installed-only", DatabaseSHA256: strings.TrimPrefix(spec.DatabaseDigest, "sha256:"), DatabaseAt: now.Add(-time.Duration(days) * 24 * time.Hour)}})
		if err != nil {
			t.Fatal(err)
		}
		host := &fixtureHost{capabilities: strongSandbox()}
		outcome, err := (HostRunner{Registry: registry, Host: host, Artifacts: store, Now: func() time.Time { return now }}).Execute(context.Background(), spec, recordDigest, recordDigest, "exec-grype-age", "vulnerability")
		if days == 4 {
			if err != nil || !host.launched || outcome.Status != NoFindings {
				t.Fatalf("fresh database did not reach inert host: %#v %v", outcome, err)
			}
		} else if err == nil || host.probed || host.launched || outcome.Status != PolicyBlocked || outcome.Coverage.ReasonCode != toolchain.ReasonDatabaseStale {
			t.Fatalf("six-day-old Grype database reached host: %#v %v", outcome, err)
		}
	}
}
