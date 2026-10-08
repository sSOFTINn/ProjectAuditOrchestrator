// Package sbomqs parses bounded, local SBOM-quality evidence. It never launches a tool.
package sbomqs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const maxOutputBytes = 64 << 20

// Result is deliberately small: a score is evidence for manual review, never a verdict.
type Result struct {
	Status string  `json:"status"`
	Reason string  `json:"reason,omitempty"`
	Score  float64 `json:"score,omitempty"`
}

// Parse accepts one bounded JSON object with an exact, finite score in 0..10.
// Duplicate keys and unknown fields are rejected so a later value cannot silently
// replace the evidence that an owner reviewed.
func Parse(raw []byte) Result {
	if len(raw) > maxOutputBytes {
		return Result{Status: "FAILED", Reason: "sbomqs output exceeds the safety limit"}
	}
	score, reportedError, err := decode(raw)
	if err != nil {
		return Result{Status: "FAILED", Reason: "malformed sbomqs JSON"}
	}
	if reportedError != "" {
		return Result{Status: "FAILED", Reason: "sbomqs reported an error"}
	}
	if score == nil || *score < 0 || *score > 10 {
		return Result{Status: "PARTIAL", Reason: "sbomqs score is missing or out of range"}
	}
	return Result{Status: "SUCCEEDED", Score: *score}
}

func decode(raw []byte) (*float64, string, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, "", errors.New("expected object")
	}
	seen := map[string]bool{}
	var score *float64
	var reportedError string
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return nil, "", errors.New("invalid or duplicate key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, "", err
		}
		switch key {
		case "run_id", "timestamp":
			if !isString(value) {
				return nil, "", errors.New("invalid sbomqs legacy envelope text")
			}
		case "creation_info":
			if !isObject(value) {
				return nil, "", errors.New("invalid sbomqs legacy creation info")
			}
		case "files":
			if score != nil {
				return nil, "", errors.New("duplicate score source")
			}
			score, err = scoreFromFiles(value)
			if err != nil {
				return nil, "", err
			}
		case "error":
			if err := json.Unmarshal(value, &reportedError); err != nil {
				return nil, "", err
			}
		default:
			return nil, "", errors.New("unknown field")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, "", errors.New("unterminated object")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, "", errors.New("trailing JSON")
	}
	return score, reportedError, nil
}

func isString(raw []byte) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil
}

func isObject(raw []byte) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && value != nil
}

func number(raw []byte) (*float64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == '"' {
		return nil, errors.New("score must be a JSON number")
	}
	var n json.Number
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return nil, err
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func scoreFromFiles(raw []byte) (*float64, error) {
	var files []json.RawMessage
	if err := json.Unmarshal(raw, &files); err != nil || len(files) != 1 {
		return nil, errors.New("sbomqs files must contain one result")
	}
	d := json.NewDecoder(bytes.NewReader(files[0]))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("sbomqs file result must be an object")
	}
	seen := map[string]bool{}
	var score *float64
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return nil, errors.New("invalid or duplicate file result key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if key == "avg_score" {
			if score != nil {
				return nil, errors.New("duplicate average score")
			}
			score, err = number(value)
			if err != nil {
				return nil, err
			}
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("unterminated file result")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing file result")
	}
	return score, nil
}
