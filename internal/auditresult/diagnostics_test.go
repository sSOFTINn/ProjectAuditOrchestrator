package auditresult

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func TestDiagnosticIntegrityPrivacyAndNoNativeAmbiguity(t *testing.T) {
	for _, mode := range []string{"valid", "failed", "tampered", "missing", "truncated", "bad-code", "foreign-execution", "duplicate", "wrong-path"} {
		t.Run(mode, func(t *testing.T) {
			root, lock, record, catalog := syntheticRun(t, nil)
			store, err := artifact.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			e := &record.Executions[0]
			ref, err := store.PutRaw("application/octet-stream", []byte("PRIVATE_SECRET\x1b[31m C:\\PRIVATE\\file"), e.ID)
			if err != nil {
				t.Fatal(err)
			}
			e.Diagnostics = []runner.DiagnosticArtifact{{Stream: "stderr", Artifact: ref}}
			e.DiagnosticCode = "COMPLETED"
			switch mode {
			case "failed":
				e.Status, e.Coverage.Status, e.DiagnosticCode = runner.Failed, runner.Failed, "SCANNER_FAILED"
			case "tampered":
				path := filepath.Join(root, filepath.FromSlash(ref.Path))
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				e.Diagnostics[0].Artifact.SHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				e.Diagnostics[0].Artifact.Path = "raw/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "truncated":
				e.Diagnostics[0].Truncated = true
			case "bad-code":
				e.DiagnosticCode = "PRIVATE_SECRET"
			case "foreign-execution":
				e.Diagnostics[0].Artifact.ExecutionID = "foreign"
			case "duplicate":
				e.Diagnostics = append(e.Diagnostics, e.Diagnostics[0])
			case "wrong-path":
				e.Diagnostics[0].Artifact.Path = "../PRIVATE_SECRET"
			}
			r := Build(root, lock, record, catalog, false)
			if r.CoverageComplete != (mode == "valid") {
				t.Fatalf("invalid coverage %s: %#v", mode, r.Coverage)
			}
			if mode == "valid" && len(r.Findings) != 8 {
				t.Fatal("diagnostics contaminated native parser")
			}
			f, err := r.Files()
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range [][]byte{f.Summary, f.PortableJSON, f.PrivateJSON} {
				if bytes.Contains(b, []byte("PRIVATE_SECRET")) || bytes.Contains(b, []byte("C:\\PRIVATE")) || bytes.ContainsRune(b, 27) {
					t.Fatal("raw diagnostic leaked")
				}
			}
			if mode == "failed" && !bytes.Contains(f.Summary, []byte("Сканер завершився зі збоєм")) {
				t.Fatal("missing plain-language explanation")
			}
		})
	}
}
