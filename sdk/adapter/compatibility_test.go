package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestShippedManifestsBindExactParserCompatibility(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "adapters"))
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{
		"syft": "1.51.1", "sbomqs": "2.1.1", "grype": "0.118.0",
		"osv-scanner": "2.5.1", "scancode": "32.5.0", "reuse": "6.2.0",
		"trivy": "0.74.0", "gitleaks": "8.30.1", "opengrep": "1.29.0", "zizmor": "1.29.0",
	}
	for id, version := range versions {
		t.Run(id, func(t *testing.T) {
			manifest, err := LoadFile(filepath.Join(root, id, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(manifest.CompatibleToolVersions, []string{version}) {
				t.Fatalf("shipped compatibility contract changed: %v", manifest.CompatibleToolVersions)
			}
			if err := manifest.AllowsToolVersion(version); err != nil {
				t.Fatal(err)
			}
			for _, unknown := range []string{"", "UNKNOWN_FUTURE_VERSION", "v" + version, version + ".1"} {
				if err := manifest.AllowsToolVersion(unknown); err == nil {
					t.Fatal("shipped parser accepted an undeclared tool version")
				}
			}
		})
	}
}

func TestLegacyManifestCanBeInspectedButCannotAuthorizeUnknownParser(t *testing.T) {
	manifest := fixtureManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := manifest.AllowsToolVersion("custom-synthetic-version"); err == nil {
		t.Fatal("an undeclared compatibility contract authorized a parser")
	}
	manifest.CompatibleToolVersions = []string{"custom-synthetic-version"}
	if err := manifest.AllowsToolVersion("custom-synthetic-version"); err != nil {
		t.Fatal(err)
	}
}

func TestManifestCompatibilitySchemaAndSDKRejectMalformedDeclarations(t *testing.T) {
	schema := loadManifestSchema(t)
	raw, err := json.Marshal(fixtureManifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		wire  string
		valid bool
	}{
		{"empty-optional", `[]`, true}, {"single", `["1.51.1"]`, true},
		{"multiple", `["1.51.1","1.50.0"]`, true}, {"null", `null`, false},
		{"duplicate", `["1.51.1","1.51.1"]`, false}, {"empty-version", `[""]`, false},
		{"spaces", `[" "]`, false}, {"leading-space", `[" 1.51.1"]`, false},
		{"trailing-space", `["1.51.1 "]`, false}, {"newline", `["1.51\n.1"]`, false},
		{"carriage-return", `["1.51\r.1"]`, false}, {"nul", `["1.51\u0000.1"]`, false},
		{"numeric", `[1.51]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			var versions any
			if err := json.Unmarshal([]byte(tc.wire), &versions); err != nil {
				t.Fatal(err)
			}
			value["compatible_tool_versions"] = versions
			schemaErr := schema.validate(value, schema)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			_, sdkErr := LoadFile(path)
			if (schemaErr == nil) != tc.valid || (sdkErr == nil) != tc.valid {
				t.Fatalf("compatibility schema/SDK disagree: schema=%v SDK=%v", schemaErr, sdkErr)
			}
		})
	}
}

func TestCanonicalCompatibilityIgnoresOrderingAndBindsSupportedVersions(t *testing.T) {
	manifest := fixtureManifest()
	manifest.CompatibleToolVersions = []string{"1.51.1", "1.50.0"}
	digest, err := Digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.CompatibleToolVersions, []string{"1.51.1", "1.50.0"}) {
		t.Fatal("canonicalization mutated the caller's compatibility list")
	}
	manifest.CompatibleToolVersions = []string{"1.50.0", "1.51.1"}
	if reordered, err := Digest(manifest); err != nil || reordered != digest {
		t.Fatal("compatibility set order changed the plan-lock digest")
	}
	manifest.CompatibleToolVersions = []string{"1.50.0", "1.52.0"}
	if changed, err := Digest(manifest); err != nil || changed == digest {
		t.Fatal("changed supported versions did not change the plan-lock digest")
	}
}
