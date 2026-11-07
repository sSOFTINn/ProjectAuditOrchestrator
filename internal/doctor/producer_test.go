package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
)

func syntheticProducer() buildinfo.Producer {
	return buildinfo.Producer{APIVersion: buildinfo.ProducerVersion, Version: "dev", Revision: "unknown", SourceState: "unknown", SourceTreeSHA256: "unknown", ExecutableSHA256: "sha256:" + strings.Repeat("a", 64), GoVersion: "go1.27.3", IdentityStatus: "DEVELOPMENT"}
}

func TestUnavailableProducerCannotProduceReadyOrMalformedIdentity(t *testing.T) {
	for _, name := range []string{"reader failure", "invalid identity"} {
		t.Run(name, func(t *testing.T) {
			path, _, d := fixture(t)
			d.producer = func() (buildinfo.Producer, error) {
				if name == "reader failure" {
					return syntheticProducer(), errors.New("synthetic unavailable executable")
				}
				return buildinfo.Producer{Version: "dev"}, nil
			}
			result := inspect(context.Background(), path, "secrets", d)
			if result.Status != "SETUP_REQUIRED" || result.ProducerStatus != "UNAVAILABLE" || result.Producer != nil {
				t.Fatalf("unavailable producer accepted: %+v", result)
			}
			failed := false
			for _, check := range result.Checks {
				if check.ID == "package.identity" && check.Status == "SETUP_REQUIRED" {
					failed = true
				}
			}
			if !failed {
				t.Fatal("identity failure omitted")
			}
			raw, err := json.Marshal(result)
			if err != nil || strings.Contains(string(raw), `"producer":`) {
				t.Fatalf("unavailable producer serialized: %s %v", raw, err)
			}
		})
	}
}
