package strictjson

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

type configuration struct {
	Name     string            `json:"name"`
	Enabled  bool              `json:"enabled"`
	Limit    int64             `json:"limit"`
	Profiles []profile         `json:"profiles"`
	Labels   map[string]string `json:"labels"`
	Expiry   time.Time         `json:"expiry"`
}

type profile struct {
	ID string `json:"id"`
}

const validConfiguration = `{"name":"fixture","enabled":false,"limit":1024,"profiles":[{"id":"one"}],"labels":{"Key":"upper","key":"lower"},"expiry":"2026-10-02T12:00:00Z"}`

func TestDecodePreservesExactStructAndDynamicMapKeys(t *testing.T) {
	var got configuration
	if err := Decode([]byte(validConfiguration), &got, len(validConfiguration)); err != nil {
		t.Fatal(err)
	}
	want := configuration{Name: "fixture", Limit: 1024, Profiles: []profile{{ID: "one"}}, Labels: map[string]string{"Key": "upper", "key": "lower"}, Expiry: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded values changed: %#v", got)
	}
	var escaped configuration
	if err := Decode([]byte(strings.Replace(validConfiguration, `"name":`, `"\u006eame":`, 1)), &escaped, len(validConfiguration)+10); err != nil || !reflect.DeepEqual(escaped, want) {
		t.Fatalf("an unambiguous escaped key changed meaning: %v", err)
	}
}

func TestDecodeRejectsAmbiguityAtEveryDepth(t *testing.T) {
	for name, bad := range map[string]string{
		"duplicate":             strings.Replace(validConfiguration, `"name":`, `"name":"other","name":`, 1),
		"escaped duplicate":     strings.Replace(validConfiguration, `"name":`, `"\u006eame":"other","name":`, 1),
		"case alias":            strings.Replace(validConfiguration, `"name":`, `"Name":`, 1),
		"nested duplicate":      strings.Replace(validConfiguration, `"id":"one"`, `"id":"one","id":"two"`, 1),
		"nested case alias":     strings.Replace(validConfiguration, `"id":"one"`, `"ID":"one"`, 1),
		"nested unknown":        strings.Replace(validConfiguration, `"id":"one"`, `"id":"one","other":false`, 1),
		"map duplicate":         strings.Replace(validConfiguration, `"Key":"upper"`, `"Key":"upper","Key":"other"`, 1),
		"escaped map duplicate": strings.Replace(validConfiguration, `"Key":"upper"`, `"Key":"upper","\u004bey":"other"`, 1),
		"root null":             `null`,
		"field null":            strings.Replace(validConfiguration, `"enabled":false`, `"enabled":null`, 1),
		"map value null":        strings.Replace(validConfiguration, `"key":"lower"`, `"key":null`, 1),
		"array item null":       strings.Replace(validConfiguration, `[{"id":"one"}]`, `[null]`, 1),
		"unknown":               strings.Replace(validConfiguration, `"name":`, `"unknown":false,"name":`, 1),
		"trailing value":        validConfiguration + " {}",
		"trailing garbage":      validConfiguration + " x",
		"incomplete":            strings.TrimSuffix(validConfiguration, "}"),
		"wrong bool":            strings.Replace(validConfiguration, `"enabled":false`, `"enabled":"false"`, 1),
		"fractional integer":    strings.Replace(validConfiguration, `"limit":1024`, `"limit":1.5`, 1),
		"overflow integer":      strings.Replace(validConfiguration, `"limit":1024`, `"limit":9223372036854775808`, 1),
		"invalid timestamp":     strings.Replace(validConfiguration, `2026-10-02T12:00:00Z`, `tomorrow`, 1),
		"invalid utf8":          string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			var got configuration
			if err := Decode([]byte(bad), &got, len(bad)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestDecodeEnforcesSizeDepthAndDestinationBounds(t *testing.T) {
	var got configuration
	if err := Decode([]byte(validConfiguration), &got, len(validConfiguration)-1); err == nil {
		t.Fatal("accepted data above byte limit")
	}
	if err := Decode([]byte(validConfiguration), got, len(validConfiguration)); err == nil {
		t.Fatal("accepted a non-pointer destination")
	}
	if err := Decode([]byte(validConfiguration), nil, len(validConfiguration)); err == nil {
		t.Fatal("accepted a missing destination")
	}
	type recursive []recursive
	for _, depth := range []int{20, 21} {
		raw := strings.Repeat("[", depth) + strings.Repeat("]", depth)
		var value recursive
		err := Decode([]byte(raw), &value, len(raw))
		// The root consumes depth zero; 21 empty array levels reach depth 20.
		if err != nil {
			t.Fatalf("accepted depth boundary rejected: %d %v", depth, err)
		}
	}
	raw := strings.Repeat("[", 22) + strings.Repeat("]", 22)
	var value recursive
	if err := Decode([]byte(raw), &value, len(raw)); err == nil {
		t.Fatal("accepted JSON above nesting limit")
	}
}
