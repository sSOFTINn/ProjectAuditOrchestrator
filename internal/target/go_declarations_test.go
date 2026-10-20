package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptyGoDeclarationsAcceptsOnlyBoundedModuleAndGoDirectives(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		empty         bool
	}{
		{"plain", "module example.invalid/main\n\ngo 1.27.1\n", true},
		{"comments-crlf", "// require example.invalid/comment v1.0.0\r\nmodule\texample.invalid/main // local main module\r\ngo 1.27\r\n", true},
		{"dependency", "module example.invalid/main\ngo 1.27.1\nrequire example.invalid/dependency v1.2.3\n", false},
		{"block", "module example.invalid/main\ngo 1.27.1\nrequire (\n)\n", false},
		{"replacement", "module example.invalid/main\ngo 1.27.1\nreplace example.invalid/dependency => ../local\n", false},
		{"tool", "module example.invalid/main\ngo 1.27.1\ntool example.invalid/tool\n", false},
		{"unknown", "module example.invalid/main\ngo 1.27.1\ngodebug default=go1.27\n", false},
		{"missing-version", "module example.invalid/main\n", false},
		{"duplicate-module", "module example.invalid/main\ngo 1.27.1\nmodule example.invalid/other\n", false},
		{"duplicate-go", "module example.invalid/main\ngo 1.27.1\ngo 1.27\n", false},
		{"bad-version", "module example.invalid/main\ngo 1.27.01\n", false},
		{"quoted-module", "module \"example.invalid/main\"\ngo 1.27.1\n", false},
		{"ambiguous-comment", "module example.invalid/main//comment\ngo 1.27.1\n", false},
		{"control", "module example.invalid/main\ngo 1.27.1\n\x00", false},
		{"invalid-utf8", "module example.invalid/main\ngo 1.27.1\n\xff", false},
		{"bom", "\xef\xbb\xbfmodule example.invalid/main\ngo 1.27.1\n", false},
		{"oversized", "module example.invalid/main\ngo 1.27.1\n// " + strings.Repeat("x", MaxGoDeclarationBytes), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := emptyGoDeclarations([]byte(tc.content)); got != tc.empty {
				t.Fatalf("empty declaration proof = %v, want %v", got, tc.empty)
			}
		})
	}
}

func TestGoDeclarationProofIsBoundToAllSnapshotInputsAndCapture(t *testing.T) {
	for _, extra := range []string{"", "nested/go.mod", "nested/go.sum", "go.work", "go.work.sum", "vendor/modules.txt", "vendor/example.invalid/dep/dep.go", "schemas/vendor/schema.json", "Go.Mod"} {
		t.Run(extra, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/private\ngo 1.27.1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if extra != "" {
				path := filepath.Join(root, filepath.FromSlash(extra))
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				// Case-insensitive Windows maps Go.Mod to go.mod: the unsupported
				// contents still make the declaration unproven on either platform.
				if err := os.WriteFile(path, []byte("unsupported-or-populated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := SnapshotRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			hashes := EmptyGoModuleHashes(snapshot)
			if (len(hashes) == 1) != (extra == "" || extra == "schemas/vendor/schema.json") {
				t.Fatalf("unproven additional input changed empty proof: %v", hashes)
			}
			if extra == "" {
				captured, err := Capture(root, filepath.Join(t.TempDir(), "input"), snapshot)
				if err != nil || strings.Join(EmptyGoModuleHashes(captured), "") != hashes[0] {
					t.Fatalf("capture lost proof: %v", err)
				}
				snapshot.Files[0].SHA256 = strings.Repeat("a", 64)
				if len(EmptyGoModuleHashes(snapshot)) != 0 {
					t.Fatal("changed content hash retained proof")
				}
			}
		})
	}
}
