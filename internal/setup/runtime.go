package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

type dockerControl struct {
	cli                           runner.PreparedCLI
	endpoint, user, config, state string
}
type boundedOutput struct {
	b        bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := b.limit - b.b.Len()
	if n > left {
		p = p[:left]
		b.overflow = true
	}
	_, _ = b.b.Write(p)
	return n, nil
}

func dockerSource(given string) (string, string, error) {
	source := given
	if source == "" {
		var e error
		source, e = exec.LookPath("docker")
		if e != nil {
			return "", "", errors.New("Docker Desktop must be installed and started separately; setup never installs Docker")
		}
	}
	source, e := filepath.EvalSymlinks(source)
	if e != nil {
		return "", "", e
	}
	source, e = filepath.Abs(source)
	if e != nil {
		return "", "", e
	}
	h, e := hashFile(source, 256<<20)
	return source, prefix(h), e
}

func newDocker(ctx context.Context, o options, state, work string) (dockerControl, error) {
	var d dockerControl
	source, digest, e := dockerSource(o.docker)
	if e != nil {
		return d, e
	}
	d.cli, e = runner.PrepareDockerCLI(ctx, source, digest, state)
	if e != nil {
		return d, e
	}
	d.endpoint, d.user, e = runner.DockerEndpoint()
	if e != nil {
		return d, e
	}
	d.state = state
	d.config = filepath.Join(work, "docker-config")
	if e = privateTree(d.config); e != nil {
		return d, e
	}
	if _, e = os.Lstat(filepath.Join(d.config, "config.json")); os.IsNotExist(e) {
		if e = writeOnce(filepath.Join(d.config, "config.json"), []byte("{}\n")); e != nil {
			return d, e
		}
	}
	raw, e := d.command(ctx, 30*time.Second, "info", "--format", "{{json .}}")
	if e != nil {
		return d, e
	}
	var info struct{ OSType, OperatingSystem, Architecture string }
	if json.Unmarshal(raw, &info) != nil || info.OSType != "linux" || !strings.Contains(strings.ToLower(info.OperatingSystem), "docker desktop") || (info.Architecture != "x86_64" && info.Architecture != "amd64") {
		return d, errors.New("setup requires the local amd64 Docker Desktop Linux VM")
	}
	return d, nil
}

func (d dockerControl) command(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	// Rehash/pin for every invocation; never inherit contexts, credentials or CLI
	// plugin configuration. Setup commands are fixed by this package.
	if h, e := hashFile(d.cli.Path, 256<<20); e != nil || prefix(h) != d.cli.SHA256 {
		return nil, errors.New("prepared Docker CLI identity changed")
	}
	path := d.cli.Path
	var release func() error
	var e error
	if runtime.GOOS == "windows" {
		release, e = runner.PinExecutable(ctx, path, d.cli.SHA256)
	} else {
		path, release, e = runner.FreezeExecutableIn(ctx, path, d.cli.SHA256, d.state)
	}
	if e != nil {
		return nil, e
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, append([]string{"--host", d.endpoint, "--config", d.config}, args...)...)
	for _, key := range []string{"SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Env = append(command.Env, "PATH="+filepath.Dir(d.cli.Path), "DOCKER_BUILDKIT=0")
	stdout, stderr := &boundedOutput{limit: 4 << 20}, &boundedOutput{limit: 64 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = 3 * time.Second
	if e := command.Run(); e != nil {
		return nil, fmt.Errorf("fixed Docker preparation command %s failed: %w; %s", args[0], e, strings.TrimSpace(stderr.b.String()))
	}
	if stdout.overflow {
		return nil, errors.New("Docker preparation output exceeds bound")
	}
	return stdout.b.Bytes(), nil
}

func (d dockerControl) buildRuntime(ctx context.Context, o options, r Recipes, p Plan, downloads map[string]string, work string) (string, error) {
	marker := filepath.Join(work, "runtime-image.json")
	if b, e := readBounded(marker, 4096); e == nil {
		var id string
		if json.Unmarshal(b, &id) == nil && imageID(id) {
			if _, e = d.command(ctx, 30*time.Second, "image", "inspect", id); e == nil {
				return id, nil
			}
		}
		return "", errors.New("recorded runtime unavailable; retain this generation and use a fresh setup root")
	}
	build := filepath.Join(work, "runtime-build")
	if e := privateTree(filepath.Join(build, "runtime-debs")); e != nil {
		return "", e
	}
	for _, a := range p.Artifacts {
		if a.Purpose == "runtime" {
			if e := copyExact(downloads[a.ID], filepath.Join(build, "runtime-debs", a.Filename), a.SHA256, a.Bytes); e != nil {
				return "", e
			}
		}
	}
	source := filepath.Join(o.packageRoot, "recipes", "runtime.Dockerfile")
	if e := copyExact(source, filepath.Join(build, "Dockerfile"), r.Payload["recipes/runtime.Dockerfile"], maxRecipeBytes); e != nil {
		return "", e
	}
	if _, e := d.command(ctx, 20*time.Minute, "pull", "--platform", "linux/amd64", r.RuntimeImage); e != nil {
		return "", e
	}
	iid := filepath.Join(work, "image-"+nonce()+".id")
	if _, e := d.command(ctx, 20*time.Minute, "build", "--platform", "linux/amd64", "--network", "none", "--pull=false", "--iidfile", iid, build); e != nil {
		return "", e
	}
	b, e := readBounded(iid, 4096)
	if e != nil {
		return "", e
	}
	id := strings.TrimSpace(string(b))
	if !imageID(id) {
		return "", errors.New("runtime build did not return an immutable image ID")
	}
	b, _ = json.Marshal(id)
	if e = writeOnce(marker, b); e != nil {
		return "", e
	}
	return id, nil
}
func imageID(s string) bool {
	return strings.HasPrefix(s, "sha256:") && digestPattern.MatchString(strings.TrimPrefix(s, "sha256:"))
}

// prepareState launches only an owned recipe against downloaded public inputs.
// A durable journal entry precedes create; cleanup uses exact ID plus labels.
func (d dockerControl) prepareState(ctx context.Context, image, mode, inputs, recipe, output string, extraMounts ...string) error {
	for _, p := range []string{inputs, recipe, output} {
		if strings.ContainsAny(p, ",\r\n") {
			return errors.New("Docker mount path contains a delimiter")
		}
	}
	s, e := installation.Open(d.state)
	if e != nil {
		return e
	}
	lease, e := s.Lock(ctx, true)
	if e != nil {
		return e
	}
	defer lease.Close()
	name := "pao-setup-" + nonce()
	record, e := lease.Begin(name, name, d.endpoint, image, d.cli.Path, d.cli.SHA256)
	if e != nil {
		return e
	}
	args := []string{"create", "--name", name, "--label", "pao.installation=" + record.InstallationID, "--label", "pao.run=" + record.ID, "--platform", "linux/amd64", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--cpus", "2", "--memory", "4g", "--memory-swap", "4g", "--user", d.user, "--tmpfs", "/tmp:rw,nosuid,nodev,size=1073741824,mode=1777", "--mount", "type=bind,source=" + inputs + ",target=/inputs,readonly", "--mount", "type=bind,source=" + recipe + ",target=/recipe,readonly", "--mount", "type=bind,source=" + output + ",target=/pao/state", "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", "/usr/local/bin/python", image, "/recipe/prepare-state.py", mode}
	if len(extraMounts) > 0 {
		index := len(args) - 3
		prefixArgs := append([]string{}, args[:index]...)
		for _, mount := range extraMounts {
			prefixArgs = append(prefixArgs, "--mount", mount)
		}
		args = append(prefixArgs, args[index:]...)
	}
	b, e := d.command(ctx, time.Minute, args...)
	if e != nil {
		return fmt.Errorf("RECOVERY_REQUIRED: preparation create outcome unknown (run %s): %w", record.ID, e)
	}
	id := strings.TrimSpace(string(b))
	if !digestPattern.MatchString(id) {
		return fmt.Errorf("RECOVERY_REQUIRED: invalid preparation container identity (run %s)", record.ID)
	}
	record, e = lease.Update(record, id, "OBSERVED")
	if e != nil {
		return e
	}
	h := runner.DockerHost{DockerPath: d.cli.Path, DockerSHA256: d.cli.SHA256, RuntimeImage: image, InstallationState: d.state}
	if _, e = runner.ReconcileLifecycle(ctx, h, lease, record, false); e != nil {
		return e
	}
	_, runErr := d.command(ctx, 35*time.Minute, "start", "--attach", id)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, cleanErr := runner.ReconcileLifecycle(cleanupCtx, h, lease, record, true)
	return errors.Join(runErr, cleanErr)
}

// Keep io/runtime references local for platform helpers introduced without
// requiring a host Python, shell or Go installation.
var _ io.Writer = (*boundedOutput)(nil)

func (d dockerControl) prepareGrype(ctx context.Context, image, gen, source, destination string, tools []toolchain.CatalogTool) error {
	if filepath.Base(source) != "vulnerability.db" || strings.ContainsAny(source, ",\r\n") {
		return errors.New("invalid Grype hydration source")
	}
	var binary, digest string
	for _, t := range tools {
		if t.Record.ID == "grype" {
			binary = filepath.Join(gen, "tools", filepath.FromSlash(t.Binary))
			digest = t.Record.SHA256
		}
	}
	if h, e := hashFile(binary, 512<<20); e != nil || h != digest {
		return errors.New("Grype hydration executable identity differs")
	}
	return d.prepareState(ctx, image, "grype", filepath.Join(gen, "work", "inputs"), filepath.Join(gen, "work", "recipe"), destination, "type=bind,source="+filepath.Dir(source)+",target=/database-source,readonly", "type=bind,source="+binary+",target=/grype,readonly")
}
