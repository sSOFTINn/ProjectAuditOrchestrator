package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadFileRejectsAmbiguousOrInvalidManifestJSON(t *testing.T) {
	raw, err := json.Marshal(fixtureManifest())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	for name, bad := range map[string]string{
		"duplicate":            strings.Replace(valid, `"id":"fixture"`, `"id":"other","id":"fixture"`, 1),
		"escaped duplicate":    strings.Replace(valid, `"id":"fixture"`, `"\u0069d":"other","id":"fixture"`, 1),
		"case alias":           strings.Replace(valid, `"id":"fixture"`, `"ID":"fixture"`, 1),
		"additional alias":     strings.Replace(valid, `"id":"fixture"`, `"id":"fixture","Id":"other"`, 1),
		"null string":          strings.Replace(valid, `"id":"fixture"`, `"id":null`, 1),
		"null safety":          strings.Replace(valid, `"writes_target":false`, `"writes_target":null`, 1),
		"missing safety":       strings.Replace(valid, `"writes_target":false,`, ``, 1),
		"missing execution":    strings.Replace(valid, `"executes_target_code":false,`, ``, 1),
		"missing prerequisite": strings.Replace(valid, `"prerequisite_kinds":["tool"],`, ``, 1),
		"unknown":              strings.TrimSuffix(valid, "}") + `,"allow_network":true}`,
		"future version":       strings.Replace(valid, ManifestVersion, "pao.dev/adapter/v1alpha99", 1),
		"trailing value":       valid + " {}",
		"trailing garbage":     valid + " x",
		"root null":            "null",
		"root array":           "[]",
		"empty":                "",
		"oversize":             strings.Repeat(" ", int(maxManifestBytes)) + valid,
		"invalid utf8":         strings.TrimSuffix(valid, "}") + ",\"limitations\":[\"" + string([]byte{0xff}) + "\"]}",
		"fractional limit":     strings.Replace(valid, `"timeout_seconds":10`, `"timeout_seconds":1.5`, 1),
		"zero timeout":         strings.Replace(valid, `"timeout_seconds":10`, `"timeout_seconds":0`, 1),
		"zero output":          strings.Replace(valid, `"max_output_bytes":1024`, `"max_output_bytes":0`, 1),
		"empty prerequisite":   strings.Replace(valid, `"prerequisite_kinds":["tool"]`, `"prerequisite_kinds":[]`, 1),
		"empty capability":     strings.Replace(valid, `"capabilities":["inventory"]`, `"capabilities":[""]`, 1),
		"wrong safety type":    strings.Replace(valid, `"writes_target":false`, `"writes_target":"false"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == valid {
				t.Fatal("negative case did not change the valid fixture")
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	for _, name := range []string{"input_indicators", "compatible_tool_versions", "allowed_environment", "success_exit_codes", "limitations"} {
		t.Run("null "+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			bad := strings.TrimSuffix(valid, "}") + `,"` + name + `":null}`
			if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Fatal("accepted explicit null optional array")
			}
		})
	}
}

func TestManifestOptionalArraysRoundTripAndCanonicalDigest(t *testing.T) {
	manifest := fixtureManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"input_indicators", "compatible_tool_versions", "allowed_environment", "success_exit_codes", "limitations"} {
		if _, exists := fields[name]; exists {
			t.Fatalf("absent optional array %s was serialized", name)
		}
	}
	digest, err := Digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil || !reflect.DeepEqual(loaded, manifest) {
		t.Fatalf("manifest round trip failed: %v", err)
	}
	for _, name := range []string{"input_indicators", "compatible_tool_versions", "allowed_environment", "success_exit_codes", "limitations"} {
		fields[name] = json.RawMessage(`[]`)
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Digest(loaded); err != nil || got != digest {
		t.Fatalf("empty optional arrays changed effective canonical digest: %s %v", got, err)
	}
	loaded.TimeoutSeconds--
	if got, err := Digest(loaded); err != nil || got == digest {
		t.Fatal("a changed manifest limit did not change canonical digest")
	}
}

func TestLoadFileRequiresEveryPublishedRequiredField(t *testing.T) {
	schema := loadManifestSchema(t)
	wireRequired := make(map[string]bool, len(requiredManifestFields))
	for _, name := range requiredManifestFields {
		wireRequired[name] = true
	}
	if len(wireRequired) != len(schema.Required) {
		t.Fatal("SDK and schema disagree on required field count")
	}
	raw, err := json.Marshal(fixtureManifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range schema.Required {
		t.Run(name, func(t *testing.T) {
			if !wireRequired[name] {
				t.Fatal("SDK does not enforce published required field")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, name)
			bad, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Fatal("accepted missing required field")
			}
		})
	}
}
