package runner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/sandbox"
)

type boundedCapture struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

// Keep the buffer named: embedding would expose ReadFrom, allowing io.Copy
// (including os/exec pipe capture) to bypass the bounded Write method.
func (b *boundedCapture) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedCapture) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if remaining < 0 {
		remaining = 0
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	// Drain the pipe after reaching the cap; never block the child on a full log.
	return n, nil
}

type commandOutput struct {
	stdout, stderr                   []byte
	stdoutTruncated, stderrTruncated bool
}
type capturedCommand func(context.Context, string, ...string) (commandOutput, error)

func captureCommand(ctx context.Context, path string, args ...string) (commandOutput, error) {
	return captureCommandLimit(ctx, int(maxDeclaredOutputBytes), path, args...)
}

func captureCommandLimit(ctx context.Context, stdoutLimit int, path string, args ...string) (commandOutput, error) {
	stdout := boundedCapture{limit: stdoutLimit}
	stderr := boundedCapture{limit: MaxDiagnosticBytes}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = dockerSafeEnvironment(os.Environ())
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	return commandOutput{stdout: stdout.Bytes(), stderr: stderr.Bytes(), stdoutTruncated: stdout.truncated, stderrTruncated: stderr.truncated}, err
}

// Docker daemon/context overrides are ambient authority. Remove inherited
// overrides and pin every invocation to the supported local endpoint; even the
// CLI's saved default context is not part of an offline PAO execution.
func dockerSafeEnvironment(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if ok && strings.HasPrefix(strings.ToUpper(name), "DOCKER_") {
			continue
		}
		result = append(result, value)
	}
	return result
}

func (h DockerHost) launchCommand(ctx context.Context, args ...string) (commandOutput, error) {
	connection, err := h.localConnection()
	if err != nil {
		return commandOutput{}, err
	}
	args = dockerEndpointArguments(connection, args)
	path := h.DockerPath
	if path == "" {
		path = "docker"
	}
	if h.runCaptured != nil {
		return h.runCaptured(ctx, path, args...)
	}
	if h.runDocker != nil { // Existing synthetic host seam, never a production fallback.
		stdout, err := h.runDocker(ctx, path, args...)
		return commandOutput{stdout: stdout, stderr: exitStderr(err)}, err
	}
	release, err := h.pinCLI(ctx, path)
	if err != nil {
		return commandOutput{}, err
	}
	defer release()
	return captureCommandLimit(ctx, sandbox.MaxWireBytes, path, args...)
}
