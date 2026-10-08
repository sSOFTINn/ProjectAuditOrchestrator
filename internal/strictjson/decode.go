// Package strictjson decodes bounded data-only configuration without ambiguous keys.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Decode rejects duplicate, case-alias and unknown struct keys at every depth,
// null values and trailing content. Dynamic map keys remain case-sensitive.
func Decode(data []byte, dst any, limit int) error {
	if len(data) > limit || !utf8.Valid(data) {
		return errors.New("invalid JSON size or UTF-8")
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("JSON destination must be a pointer")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := value(d, t.Elem(), 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	return json.Unmarshal(data, dst)
}

func value(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 20 {
		return errors.New("JSON nesting exceeds limit")
	}
	x, err := d.Token()
	if err != nil {
		return err
	}
	if x == nil {
		return errors.New("null configuration value")
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := x.(string); !ok {
			return errors.New("timestamp must be a string")
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		if x != json.Delim('{') {
			return errors.New("expected JSON object")
		}
		fields := map[string]reflect.Type{}
		if t.Kind() == reflect.Struct {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					fields[name] = f.Type
				}
			}
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
			var child reflect.Type
			if t.Kind() == reflect.Map {
				child = t.Elem()
			} else {
				child = fields[name]
				if child == nil {
					return errors.New("unknown or case-variant JSON key")
				}
			}
			if err := value(d, child, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unclosed JSON object")
		}
	case reflect.Slice:
		if x != json.Delim('[') {
			return errors.New("expected JSON array")
		}
		for d.More() {
			if err := value(d, t.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unclosed JSON array")
		}
	case reflect.String:
		if _, ok := x.(string); !ok {
			return errors.New("expected JSON string")
		}
	default:
		if _, ok := x.(json.Delim); ok {
			return errors.New("expected JSON scalar")
		}
	}
	return nil
}
