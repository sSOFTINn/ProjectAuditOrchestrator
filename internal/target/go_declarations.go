package target

import (
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Only this deliberately small subset can prove an empty declared dependency
// set. Everything else (including valid but unsupported directives) is unknown.
// No package manager, target code, toolchain or network request is executed.
const GoModNoDependenciesV1 = "go-mod-module-go-only/v1"
const MaxGoDeclarationBytes = 64 << 10

var goDeclarationVersion = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$`)

func emptyGoDeclarations(content []byte) bool {
	if len(content) == 0 || len(content) > MaxGoDeclarationBytes || !utf8.Valid(content) {
		return false
	}
	for _, b := range content {
		if b >= 127 || (b < 32 && b != '\n' && b != '\r' && b != '\t') {
			return false
		}
	}
	module, version := false, false
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			// Reject ambiguous token/comment boundaries rather than accepting a
			// truncated module path as evidence.
			if i > 0 && line[i-1] != ' ' && line[i-1] != '\t' {
				return false
			}
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		words := strings.Fields(line)
		if len(words) != 2 {
			return false
		}
		switch words[0] {
		case "module":
			if module || !plainModulePath(words[1]) {
				return false
			}
			module = true
		case "go":
			if version || !goDeclarationVersion.MatchString(words[1]) {
				return false
			}
			version = true
		default:
			return false
		}
	}
	return module && version
}

func plainModulePath(value string) bool {
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") {
			return false
		}
		for _, b := range []byte(part) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))) {
				return false
			}
		}
	}
	return true
}

// EmptyGoModuleHashes requires every Go manifest to have the same bounded
// content proof. Checksums, workspaces and vendored inputs prevent the empty
// declaration exception; one empty module cannot mask another unproven module.
func EmptyGoModuleHashes(s Snapshot) []string {
	if !s.Complete || len(s.ReparsePaths) != 0 || !VerifySnapshotIdentity(s) {
		return nil
	}
	seen := map[string]bool{}
	for _, f := range s.Files {
		name := strings.ToLower(filepath.Base(filepath.FromSlash(f.Path)))
		goVendorInput := strings.Contains("/"+strings.ToLower(f.Path)+"/", "/vendor/") &&
			(name == "modules.txt" || name == "go.mod" || strings.HasSuffix(name, ".go"))
		if name == "go.sum" || name == "go.work" || name == "go.work.sum" || goVendorInput {
			return nil
		}
		if name != "go.mod" {
			continue
		}
		if filepath.Base(filepath.FromSlash(f.Path)) != "go.mod" || f.Status != "HASHED" || f.Size <= 0 || f.Size > MaxGoDeclarationBytes || f.GoModDeclaration != GoModNoDependenciesV1 || len(f.SHA256) != 64 || strings.ToLower(f.SHA256) != f.SHA256 {
			return nil
		}
		if _, err := hex.DecodeString(f.SHA256); err != nil {
			return nil
		}
		seen["sha256:"+f.SHA256] = true
		if len(seen) > 1000 {
			return nil
		}
	}
	var hashes []string
	for hash := range seen {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	return hashes
}
