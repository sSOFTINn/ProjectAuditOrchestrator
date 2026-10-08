// pao-sandbox is PAO's static Linux supervisor. It runs only in the approved VM;
// scanners never receive a writable host mount. No shell is involved.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/sandbox"
)

type capture struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (c *capture) Write(data []byte) (int, error) {
	n := len(data)
	remaining := c.limit - c.buffer.Len()
	if len(data) > remaining {
		data = data[:remaining]
		c.truncated = true
	}
	_, _ = c.buffer.Write(data)
	return n, nil
}

func main() {
	// Refuse native use and require the supervisor to own the container lifetime.
	if !isContainerSupervisor() || len(os.Args) != 2 || len(os.Args[1]) > 128<<10 {
		os.Exit(125)
	}
	data, err := base64.RawURLEncoding.DecodeString(os.Args[1])
	if err != nil {
		os.Exit(125)
	}
	var request sandbox.Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Validate() != nil {
		os.Exit(125)
	}
	result := supervise(request)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(125)
	}
}

func supervise(request sandbox.Request) sandbox.Result {
	result := sandbox.Result{Version: sandbox.Version, Files: map[string][]byte{}}
	stdoutLimit := request.MaxBytes
	// Progress from file-producing scanners must not consume the report budget.
	if len(request.Files) > 0 && stdoutLimit > sandbox.MaxDiagnosticBytes {
		stdoutLimit = sandbox.MaxDiagnosticBytes
	}
	stdout := capture{limit: int(stdoutLimit)}
	stderr := capture{limit: sandbox.MaxDiagnosticBytes}
	command := exec.Command(request.Entrypoint, request.Arguments...)
	command.Stdin = nil
	command.Stdout, command.Stderr = &stdout, &stderr
	command.WaitDelay = 2 * time.Second
	err := command.Run()
	// Stop surviving descendants before reading result paths. As container PID 1
	// this excludes the supervisor itself and cannot affect any host process.
	teardownErr := stopDescendants()
	if err == nil {
		code := 0
		result.ExitCode = &code
	} else {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			result.ExitCode = &code
		} else {
			result.StartFailed = true
		}
	}
	result.Stdout, result.Stderr = stdout.buffer.Bytes(), stderr.buffer.Bytes()
	result.StdoutTruncated, result.StderrTruncated = stdout.truncated, stderr.truncated
	if teardownErr != nil {
		result.StartFailed = true
		return result
	}
	remaining := request.MaxBytes - int64(len(result.Stdout))
	for _, name := range request.Files {
		contents, limited, err := outputFile(name, remaining)
		if err != nil {
			result.UnsafeFiles = append(result.UnsafeFiles, name)
		} else {
			result.Files[name] = contents
			remaining -= int64(len(contents))
		}
		result.OutputLimited = result.OutputLimited || limited
	}
	return result
}

func outputFile(name string, budget int64) ([]byte, bool, error) {
	if !sandbox.SafeFile(name) {
		return nil, false, errors.New("unsafe output")
	}
	root := "/pao/out"
	for _, part := range strings.Split(name, "/") {
		root = filepath.Join(root, part)
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, false, errors.New("redirected output")
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, errors.New("nonregular output")
	}
	if info.Size() > budget {
		return nil, true, errors.New("output limit")
	}
	file, err := os.Open(root)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errors.New("output replaced")
	}
	contents, err := io.ReadAll(io.LimitReader(file, budget+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, false, errors.New("output changed")
	}
	if int64(len(contents)) > budget {
		return nil, true, errors.New("output limit")
	}
	if int64(len(contents)) != opened.Size() {
		return nil, false, errors.New("output size changed")
	}
	return contents, false, nil
}
