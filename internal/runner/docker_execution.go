package runner

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
)

func (h DockerHost) prepareExecution(ctx context.Context, spec ExecutionSpec) (IsolationHost, func() error, error) {
	if h.preparedNative || h.runDocker != nil || h.runCaptured != nil {
		return h, func() error { return nil }, nil
	}
	var cleanups []func() error
	cleanup := func() error {
		var err error
		for index := len(cleanups) - 1; index >= 0; index-- {
			err = errors.Join(err, cleanups[index]())
		}
		return err
	}
	parent := filepath.Dir(spec.TemporaryDir)
	if runtime.GOOS == "windows" {
		release, err := PinExecutable(ctx, h.DockerPath, h.DockerSHA256)
		if err != nil {
			return nil, nil, err
		}
		cleanups = append(cleanups, release)
	} else {
		path, release, err := FreezeExecutableIn(ctx, h.DockerPath, h.DockerSHA256, parent)
		if err != nil {
			return nil, nil, err
		}
		h.DockerPath = path
		cleanups = append(cleanups, release)
	}
	supervisor, err := h.supervisorPath()
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	digest := h.SandboxSHA256
	if h.SandboxPath == "" {
		digest = buildinfo.SandboxSHA256
	}
	path, release, err := FreezeExecutableIn(ctx, supervisor, digest, parent)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	h.SandboxPath, h.SandboxSHA256, h.preparedNative = path, digest, true
	cleanups = append(cleanups, release)
	return h, cleanup, nil
}

// Standalone Windows probes retain the actual executable and ancestors across
// process creation. Configured Linux execution uses a private copy instead.
func (h DockerHost) pinCLI(ctx context.Context, path string) (func() error, error) {
	if h.preparedNative {
		return func() error { return nil }, nil
	}
	return PinExecutable(ctx, path, h.DockerSHA256)
}
