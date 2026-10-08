package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestManifestSchemaRequiresRuntimeSecurityFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "adapter-manifest-v1alpha2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"api_version", "fixed_arguments", "required_sandbox", "fixture_cases", "max_output_bytes", "redaction_class"} {
		found := false
		for _, required := range schema.Required {
			found = found || required == name
		}
		if !found || schema.Properties[name] == nil {
			t.Fatalf("schema does not require runtime field %q", name)
		}
	}
	if schema.AdditionalProperties {
		t.Fatal("schema permits undeclared manifest fields")
	}
}

func TestEveryMVPManifestMatchesPublishedSchema(t *testing.T) {
	schema := loadManifestSchema(t)
	paths, err := filepath.Glob(filepath.Join("..", "..", "adapters", "*", "manifest.json"))
	if err != nil || len(paths) != 10 {
		t.Fatalf("expected all ten shipped adapter manifests: %d %v", len(paths), err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if err := schema.validate(value, schema); err != nil {
				t.Fatalf("published schema rejected shipped manifest: %v", err)
			}
		})
	}
}

func TestManifestSchemaSuccessExitCodesMatchSDKRules(t *testing.T) {
	schema := loadManifestSchema(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "adapters", "gitleaks", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		codes string
		valid bool
	}{
		{"absent", "", true}, {"default-empty", `[]`, true},
		{"zero", `[0]`, true}, {"findings", `[0,1]`, true}, {"maximum", `[0,255]`, true},
		{"nonzero-only", `[1]`, false}, {"duplicate", `[0,0]`, false},
		{"negative", `[0,-1]`, false}, {"too-large", `[0,256]`, false},
		{"fractional", `[0,1.5]`, false}, {"string", `[0,"1"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			delete(value, "success_exit_codes")
			if tc.codes != "" {
				var codes any
				if err := json.Unmarshal([]byte(tc.codes), &codes); err != nil {
					t.Fatal(err)
				}
				value["success_exit_codes"] = codes
			}
			schemaErr := schema.validate(value, schema)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var manifest Manifest
			sdkErr := json.Unmarshal(encoded, &manifest)
			if sdkErr == nil {
				sdkErr = manifest.Validate()
			}
			if (schemaErr == nil) != tc.valid || (sdkErr == nil) != tc.valid {
				t.Fatalf("schema/SDK disagree with expected validity %t: schema=%v SDK=%v", tc.valid, schemaErr, sdkErr)
			}
		})
	}
}

// manifestSchema implements only the JSON Schema keywords used by the published
// manifest contract. This keeps schema checks offline without a runtime dependency.
// Strict decoding rejects new keywords until their semantics are tested here.
type manifestSchema struct {
	Schema               string                     `json:"$schema"`
	ID                   string                     `json:"$id"`
	Ref                  string                     `json:"$ref"`
	Defs                 map[string]*manifestSchema `json:"$defs"`
	Type                 string                     `json:"type"`
	Const                json.RawMessage            `json:"const"`
	Properties           map[string]*manifestSchema `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	Items                *manifestSchema            `json:"items"`
	Contains             *manifestSchema            `json:"contains"`
	AnyOf                []*manifestSchema          `json:"anyOf"`
	UniqueItems          bool                       `json:"uniqueItems"`
	MinItems             *int                       `json:"minItems"`
	MaxItems             *int                       `json:"maxItems"`
	MinLength            *int                       `json:"minLength"`
	Pattern              string                     `json:"pattern"`
	Minimum              *float64                   `json:"minimum"`
	Maximum              *float64                   `json:"maximum"`
}

func loadManifestSchema(t *testing.T) *manifestSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "adapter-manifest-v1alpha2.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var schema manifestSchema
	if err := decoder.Decode(&schema); err != nil {
		t.Fatalf("unsupported published schema: %v", err)
	}
	return &schema
}

func (s *manifestSchema) validate(value any, root *manifestSchema) error {
	if s.Ref != "" {
		if !strings.HasPrefix(s.Ref, "#/$defs/") || root.Defs[strings.TrimPrefix(s.Ref, "#/$defs/")] == nil {
			return fmt.Errorf("unsupported local schema reference %q", s.Ref)
		}
		if err := root.Defs[strings.TrimPrefix(s.Ref, "#/$defs/")].validate(value, root); err != nil {
			return err
		}
	}
	if len(s.Const) != 0 {
		var expected any
		if err := json.Unmarshal(s.Const, &expected); err != nil {
			return err
		}
		if !reflect.DeepEqual(value, expected) {
			return fmt.Errorf("value does not match const %s", s.Const)
		}
	}
	if len(s.AnyOf) != 0 {
		matched := false
		for _, alternative := range s.AnyOf {
			matched = matched || alternative.validate(value, root) == nil
		}
		if !matched {
			return fmt.Errorf("no anyOf alternative matched")
		}
	}
	switch s.Type {
	case "":
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("expected object")
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("expected array")
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string")
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("expected integer")
		}
	default:
		return fmt.Errorf("unsupported schema type %q", s.Type)
	}
	switch v := value.(type) {
	case map[string]any:
		for _, required := range s.Required {
			if _, exists := v[required]; !exists {
				return fmt.Errorf("missing required property %q", required)
			}
		}
		for key, child := range v {
			if property := s.Properties[key]; property != nil {
				if err := property.validate(child, root); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			} else if s.AdditionalProperties != nil && !*s.AdditionalProperties {
				return fmt.Errorf("undeclared property %q", key)
			}
		}
	case []any:
		if (s.MinItems != nil && len(v) < *s.MinItems) || (s.MaxItems != nil && len(v) > *s.MaxItems) {
			return fmt.Errorf("array length is outside bounds")
		}
		contains := s.Contains == nil
		for index, item := range v {
			if s.Items != nil {
				if err := s.Items.validate(item, root); err != nil {
					return fmt.Errorf("item %d: %w", index, err)
				}
			}
			if s.Contains != nil && s.Contains.validate(item, root) == nil {
				contains = true
			}
			if s.UniqueItems {
				for _, previous := range v[:index] {
					if reflect.DeepEqual(previous, item) {
						return fmt.Errorf("duplicate array item")
					}
				}
			}
		}
		if !contains {
			return fmt.Errorf("required array item is absent")
		}
	case string:
		if s.MinLength != nil && utf8.RuneCountInString(v) < *s.MinLength {
			return fmt.Errorf("string is too short")
		}
		if s.Pattern != "" {
			matched, err := regexp.MatchString(s.Pattern, v)
			if err != nil || !matched {
				return fmt.Errorf("string does not match pattern %q", s.Pattern)
			}
		}
	case float64:
		if (s.Minimum != nil && v < *s.Minimum) || (s.Maximum != nil && v > *s.Maximum) {
			return fmt.Errorf("number is outside bounds")
		}
	}
	return nil
}
