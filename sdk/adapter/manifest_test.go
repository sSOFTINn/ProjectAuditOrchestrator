package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestValidateSafetyDefaults(t *testing.T) {
	m := fixtureManifest()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Network = "allowed"
	if err := m.Validate(); err == nil {
		t.Fatal("unsafe network manifest accepted")
	}
}

func TestManifestRequiresFullStrongIsolationAndFixtures(t *testing.T) {
	m := fixtureManifest()
	m.RequiredSandbox = m.RequiredSandbox[:1]
	if err := m.Validate(); err == nil {
		t.Fatal("incomplete sandbox was accepted")
	}
	m = fixtureManifest()
	m.FixtureCases = []string{"success"}
	if err := m.Validate(); err == nil {
		t.Fatal("incomplete fixture matrix was accepted")
	}
}

func TestManifestRejectsUndeclaredOrMalformedEnvironment(t *testing.T) {
	m := fixtureManifest()
	m.AllowedEnvironment = []string{"HOME"}
	if err := m.AllowsEnvironment(map[string]string{"HOME": "/pao/state"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AllowsEnvironment(map[string]string{"UNDECLARED": "value"}); err == nil {
		t.Fatal("undeclared environment was accepted")
	}
	m.AllowedEnvironment = []string{"bad-name"}
	if err := m.Validate(); err == nil {
		t.Fatal("malformed allowed environment name was accepted")
	}
}

func TestCanonicalManifestDigestIgnoresSetOrdering(t *testing.T) {
	first := fixtureManifest()
	second := fixtureManifest()
	second.Capabilities = []string{"sbom", "inventory"}
	first.Capabilities = []string{"inventory", "sbom"}
	firstJSON, err := CanonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := CanonicalJSON(second)
	if err != nil || string(firstJSON) != string(secondJSON) {
		t.Fatalf("manifest ordering changed canonical content: %s %s %v", firstJSON, secondJSON, err)
	}
	firstDigest, _ := Digest(first)
	secondDigest, _ := Digest(second)
	if firstDigest != secondDigest {
		t.Fatal("manifest ordering changed digest")
	}
}

func TestLoadFileRejectsUnknownFieldsAndLoadsValidatedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	raw, err := json.Marshal(fixtureManifest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil || loaded.ID != "fixture" {
		t.Fatalf("valid manifest did not load: %#v %v", loaded, err)
	}
	withUnknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if err := os.WriteFile(path, withUnknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}

func TestEveryMVPManifestLoadsUnderStrictContract(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "adapters"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"syft", "sbomqs", "grype", "osv-scanner", "scancode", "reuse", "trivy", "gitleaks", "opengrep", "zizmor"} {
		t.Run(id, func(t *testing.T) {
			manifest, err := LoadFile(filepath.Join(root, id, "manifest.json"))
			if err != nil || manifest.ID != id {
				t.Fatalf("MVP manifest did not validate: %#v %v", manifest, err)
			}
		})
	}
}

func fixtureManifest() Manifest {
	return Manifest{APIVersion: ManifestVersion, ID: "fixture", DisplayName: "Fixture", Upstream: "https://example.test/fixture", Capabilities: []string{"inventory"}, SupportedPlatforms: []string{"windows-amd64"}, InputKinds: []string{"directory"}, OutputKinds: []string{"json"}, SourceLicense: "MIT", Redistribution: "user-installed-only", Network: "never-during-audit", TimeoutSeconds: 10, ParserSchema: "fixture/v1", FixedArguments: []string{"scan", "${target}"}, RequiredSandbox: []string{"container-vm", "repository-read-only", "temporary-write-only", "network-denied", "environment-sanitized", "process-tree-controlled", "cpu-limited", "memory-limited", "filesystem-isolated", "clean-runtime"}, PrerequisiteKinds: []string{"tool"}, FixtureCases: []string{"success", "empty", "partial", "error", "malformed"}, MaxOutputBytes: 1024, RedactionClass: "standard"}
}
