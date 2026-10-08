package runner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countingOutputReader struct{ read int }

func (r *countingOutputReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.read += len(p)
	return len(p), nil
}

func TestOutputReaderRejectsGrowthAndAlwaysBoundsRead(t *testing.T) {
	for _, tc := range []struct {
		body     string
		expected int64
		valid    bool
	}{
		{"12345678", 8, true},
		{"1234567", 7, true},
		{"12345678", 7, false},
		{"1234567", 8, false},
		{"123456789", 8, false},
		{"123456789", 9, false},
	} {
		data, err := readOutputBytes(strings.NewReader(tc.body), tc.expected, 8)
		if (err == nil) != tc.valid || (tc.valid && string(data) != tc.body) || (!tc.valid && data != nil) {
			t.Fatalf("growth/bound result for %#v: %q %v", tc, data, err)
		}
	}
	unending := &countingOutputReader{}
	if data, err := readOutputBytes(unending, 8, 8); err == nil || data != nil || unending.read != 9 {
		t.Fatalf("unbounded reader consumed %d bytes: %v", unending.read, err)
	}
}

func TestDeclaredOutputReaderRejectsUnsafeAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nested", "result.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readDeclaredOutput(root, "nested/result.json"); err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("safe declared output rejected: %q %v", data, err)
	}
	for _, name := range []string{"../result.json", "/result.json", "nested", "missing.json"} {
		if data, err := readDeclaredOutput(root, name); err == nil || data != nil {
			t.Fatalf("unsafe output was accepted: %q", name)
		}
	}
	file, err := os.OpenFile(filepath.Join(root, "oversized.json"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(maxDeclaredOutputBytes, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := readDeclaredOutput(root, "oversized.json"); err == nil || data != nil {
		t.Fatal("oversized declared output was accepted")
	}
}

func TestDeclaredOutputReaderRejectsSymlinkAncestor(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "result.json"), []byte(`{"private":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Skipf("symlink creation unavailable; Windows junction case is separate: %v", err)
	}
	if data, err := readDeclaredOutput(root, "redirect/result.json"); err == nil || data != nil {
		t.Fatal("declared output followed a redirected parent")
	}
}

func TestAdditionalOutputUsesBoundedReaderAndKeepsFailureExplicit(t *testing.T) {
	for _, valid := range []bool{false, true} {
		spec, registry, store := verifiedFixture(t)
		spec.AdditionalOutputs = []DeclaredOutput{{File: "result.json", MediaType: "application/json"}}
		if valid {
			if err := os.WriteFile(filepath.Join(spec.TemporaryDir, "result.json"), []byte(`{"extra":true}`), 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Mkdir(filepath.Join(spec.TemporaryDir, "result.json"), 0700); err != nil {
			t.Fatal(err)
		}
		host := &diagnosticFixtureHost{fixtureHost: fixtureHost{capabilities: strongSandbox()}, result: LaunchResult{Status: Succeeded, Reason: "synthetic", MediaType: "application/json", RawOutput: []byte(`{}`)}}
		got, err := (HostRunner{Registry: registry, Host: host, Artifacts: store}).Execute(context.Background(), spec, recordDigest, recordDigest, "output-reader", "inventory")
		if valid {
			if err != nil || got.Status != Succeeded || len(got.RawArtifacts) != 2 {
				t.Fatalf("valid additional output changed behavior: %#v %v", got, err)
			}
		} else if err == nil || got.Status != Failed || got.DiagnosticCode != "EVIDENCE_STORE_FAILED" || len(got.RawArtifacts) != 1 {
			t.Fatalf("unsafe additional output was not explicit failure: %#v %v", got, err)
		}
	}
}
