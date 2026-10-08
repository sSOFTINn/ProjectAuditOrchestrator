// Package sandbox defines the bounded protocol between PAO and its own
// supervisor running as PID 1 inside the approved Docker Desktop VM.
package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

const (
	Version                  = "pao.dev/sandbox/v1"
	MaxOutputBytes     int64 = 64 << 20
	MaxDiagnosticBytes       = 256 << 10
	MaxWireBytes             = 90 << 20 // base64 encoding of bounded results, plus metadata
	ScratchBytes             = 128 << 20
	MaxFiles                 = 16
)

type Request struct {
	Version    string   `json:"version"`
	Entrypoint string   `json:"entrypoint"`
	Arguments  []string `json:"arguments"`
	Files      []string `json:"files"`
	MaxBytes   int64    `json:"max_bytes"`
}

type Result struct {
	Version         string            `json:"version"`
	ExitCode        *int              `json:"exit_code"`
	StartFailed     bool              `json:"start_failed"`
	Stdout          []byte            `json:"stdout"`
	Stderr          []byte            `json:"stderr"`
	StdoutTruncated bool              `json:"stdout_truncated"`
	StderrTruncated bool              `json:"stderr_truncated"`
	Files           map[string][]byte `json:"files"`
	UnsafeFiles     []string          `json:"unsafe_files"`
	OutputLimited   bool              `json:"output_limited"`
}

func (r Request) Validate() error {
	if r.Version != Version || r.MaxBytes <= 0 || r.MaxBytes > MaxOutputBytes || len(r.Files) > MaxFiles || len(r.Arguments) == 0 || len(r.Arguments) > 128 {
		return errors.New("invalid sandbox request bounds")
	}
	if (!strings.HasPrefix(r.Entrypoint, "/pao/tool/") && !strings.HasPrefix(r.Entrypoint, "/pao/state/")) || path.Clean(r.Entrypoint) != r.Entrypoint || strings.ContainsRune(r.Entrypoint, '\x00') {
		return errors.New("invalid sandbox entrypoint")
	}
	seen := map[string]bool{}
	for _, name := range r.Files {
		if !SafeFile(name) || seen[name] {
			return errors.New("invalid sandbox output declaration")
		}
		seen[name] = true
	}
	for _, arg := range r.Arguments {
		if arg == "" || strings.ContainsRune(arg, '\x00') {
			return errors.New("invalid sandbox argument")
		}
	}
	return nil
}

func SafeFile(name string) bool {
	return name != "" && name != "." && path.Clean(name) == name && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00")
}

// Decode admits only the fixed supervisor envelope and its declared outputs.
// The outer capture bound also limits allocations made by encoding/json.
func Decode(data []byte, request Request) (Result, error) {
	var result Result
	if len(data) > MaxWireBytes {
		return result, errors.New("sandbox envelope exceeds its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("trailing sandbox envelope")
	}
	if result.Version != Version || len(result.Stderr) > MaxDiagnosticBytes {
		return result, errors.New("invalid sandbox response")
	}
	allowed := map[string]bool{}
	for _, name := range request.Files {
		allowed[name] = true
	}
	total := int64(len(result.Stdout))
	for name, contents := range result.Files {
		if !allowed[name] {
			return result, errors.New("undeclared sandbox output")
		}
		total += int64(len(contents))
	}
	for _, name := range result.UnsafeFiles {
		if !allowed[name] {
			return result, errors.New("undeclared unsafe output")
		}
	}
	if total > request.MaxBytes {
		return result, errors.New("sandbox output exceeds its aggregate limit")
	}
	return result, nil
}
