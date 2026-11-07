package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

const installationLabel = "pao.installation"
const runLabel = "pao.run"

var fullContainerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// DockerEndpoint resolves only the supported local Desktop endpoint and VM UID.
func DockerEndpoint() (endpoint, user string, err error) {
	c, err := (DockerHost{}).localConnection()
	return c.endpoint, c.user, err
}

func (h DockerHost) launchTrackedCommand(ctx context.Context, spec ExecutionSpec, args []string) (commandOutput, error) {
	// Existing in-package synthetic seams do not create real containers. Tests
	// that exercise persistence supply a real temporary installation explicitly.
	if h.InstallationState == "" && (h.runDocker != nil || h.runCaptured != nil) {
		return h.launchCommand(ctx, args...)
	}
	s, err := installation.Open(h.InstallationState)
	if err != nil {
		return commandOutput{}, err
	}
	lease, err := s.Lock(ctx, true)
	if err != nil {
		return commandOutput{}, err
	}
	defer lease.Close()
	c, err := h.localConnection()
	if err != nil {
		return commandOutput{}, err
	}
	recoveryPath := h.recoveryDockerPath
	if recoveryPath == "" {
		recoveryPath = h.DockerPath
	}
	record, err := lease.Begin(h.AuditID, spec.ContainerName, c.endpoint, h.RuntimeImage, recoveryPath, h.DockerSHA256)
	if err != nil {
		return commandOutput{}, err
	}
	// Create separately from attach so the full ID is durable before execution.
	// If creation has an ambiguous transport outcome, leave PENDING for recovery.
	create := append([]string{"create", "--label", installationLabel + "=" + record.InstallationID, "--label", runLabel + "=" + record.ID}, args[1:]...)
	created, err := h.command(ctx, create...)
	if err != nil {
		return commandOutput{}, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: err}
	}
	id := strings.TrimSpace(string(created))
	if !fullContainerID.MatchString(id) {
		return commandOutput{}, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: errors.New("Docker create returned an invalid full container ID")}
	}
	record, err = lease.Update(record, id, "OBSERVED")
	if err != nil {
		return commandOutput{}, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: err}
	}
	// Before start, prove that the daemon's ID has our exact labels and image.
	if _, present, err := observeLifecycle(ctx, h, record); err != nil || !present {
		if err == nil {
			err = errors.New("created container disappeared before start")
		}
		return commandOutput{}, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: err}
	}
	admissionErr := h.validateRuntimeReview()
	if admissionErr == nil && spec.launchAdmission != nil {
		admissionErr = spec.launchAdmission()
	}
	if admissionErr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := ReconcileLifecycle(cleanupCtx, h, lease, record, true); err != nil {
			return commandOutput{}, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: err}
		}
		return commandOutput{}, admissionErr
	}
	output, commandErr := h.launchCommand(ctx, "start", "--attach", id)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if h.preparation != nil && spec.Environment["PAO_QUOTA_FIXTURE"] == "timeout" {
		// A deadline consumed by setup work is not a successful timeout test.
		// Before removing this exact owned container, prove it actually started
		// and was still running after the host interrupted its attached command.
		var startErr error
		output.containerStarted, startErr = observeRunningLifecycle(cleanupCtx, h, record)
		commandErr = errors.Join(commandErr, startErr)
	}
	if _, err := ReconcileLifecycle(cleanupCtx, h, lease, record, true); err != nil {
		return output, &UnconfirmedContainerCleanupError{ContainerName: record.ContainerName, RunID: record.ID, Cause: err}
	}
	output.lifecycleID = record.ID
	return output, commandErr
}

func observeRunningLifecycle(ctx context.Context, h DockerHost, record installation.Run) (bool, error) {
	id, present, err := observeLifecycle(ctx, h, record)
	if err != nil || !present {
		return false, errors.Join(err, errors.New("timeout probe container is unavailable for start verification"))
	}
	raw, err := h.command(ctx, "container", "inspect", "--format", "{{json .State}}", id)
	if err != nil {
		return false, err
	}
	var state struct {
		Running   bool      `json:"Running"`
		StartedAt time.Time `json:"StartedAt"`
	}
	if json.Unmarshal(raw, &state) != nil || !state.Running || state.StartedAt.IsZero() {
		return false, errors.New("timeout probe did not prove a running container")
	}
	return true, nil
}

// ReconcileLifecycle only mutates an exactly identified PAO container when
// remove=true. The caller must hold the exclusive installation lease. With
// remove=false it validates/observes without writing any journal record.
func ReconcileLifecycle(ctx context.Context, h DockerHost, lease *installation.Lease, r installation.Run, remove bool) (installation.Run, error) {
	if !h.preparedNative && h.runDocker == nil && h.runCaptured == nil {
		prepared, release, err := prepareReadOnlyControl(ctx, h, h.InstallationState)
		if err != nil {
			return r, err
		}
		defer release()
		h = prepared
	}
	id, present, err := observeLifecycle(ctx, h, r)
	if err != nil {
		return r, err
	}
	if !remove {
		return r, nil
	}
	if r.Status == "VERIFIED_ABSENT" {
		if present {
			return r, errors.New("completed lifecycle unexpectedly has a container")
		}
		return r, nil
	}
	if present {
		if r.ContainerID == "" {
			r, err = lease.Update(r, id, "OBSERVED")
			if err != nil {
				return r, err
			}
		}
		if _, err = h.command(ctx, "rm", "--force", id); err != nil {
			// --rm can race our cleanup. A subsequent successful absence proof is
			// authoritative; the remove error alone never is.
			_, exists, probeErr := observeLifecycle(ctx, h, r)
			if probeErr != nil || exists {
				return r, errors.Join(err, probeErr, errors.New("owned container teardown is unconfirmed"))
			}
		}
	}
	_, present, err = observeLifecycle(ctx, h, r)
	if err != nil || present {
		return r, errors.Join(err, errors.New("owned container absence was not confirmed"))
	}
	return lease.Update(r, r.ContainerID, "VERIFIED_ABSENT")
}

type RecoveryResult struct {
	Version          string `json:"version"`
	RunID            string `json:"run_id"`
	InstallationID   string `json:"installation_id"`
	ContainerID      string `json:"container_id,omitempty"`
	ContainerPresent bool   `json:"container_present"`
	Status           string `json:"status"`
	Changed          bool   `json:"changed"`
}

// RecoverInstallationRun deliberately uses the journaled executable generation
// and endpoint. Expired scanner approvals do not prevent safe teardown, while
// a changed executable or identity still blocks it.
func RecoverInstallationRun(ctx context.Context, state, id string, apply bool) (RecoveryResult, error) {
	result := RecoveryResult{Version: "pao.dev/recovery-result/v1", RunID: id}
	s, err := installation.Open(state)
	if err != nil {
		return result, err
	}
	l, err := s.Lock(ctx, apply)
	if err != nil {
		return result, err
	}
	defer l.Close()
	r, err := s.Read(id)
	if err != nil {
		return result, err
	}
	result.InstallationID = s.ID()
	result.Status = r.Status
	h := DockerHost{DockerPath: r.DockerPath, DockerSHA256: r.DockerSHA256, RuntimeImage: r.RuntimeImage, InstallationState: state}
	h, release, err := prepareReadOnlyControl(ctx, h, state)
	if err != nil {
		return result, err
	}
	defer release()
	containerID, present, err := observeLifecycle(ctx, h, r)
	if err != nil {
		return result, err
	}
	result.ContainerID, result.ContainerPresent = containerID, present
	if !apply {
		return result, nil
	}
	updated, err := ReconcileLifecycle(ctx, h, l, r, true)
	if err != nil {
		return result, err
	}
	result.Status, result.Changed, result.ContainerPresent = updated.Status, updated != r, false
	result.ContainerID = updated.ContainerID
	return result, nil
}

func observeLifecycle(ctx context.Context, h DockerHost, r installation.Run) (string, bool, error) {
	c, err := h.localConnection()
	if err != nil {
		return "", false, err
	}
	if c.endpoint != r.Endpoint || h.RuntimeImage != r.RuntimeImage || h.DockerSHA256 != r.DockerSHA256 {
		return "", false, errors.New("recovery endpoint, CLI or runtime identity differs from journal")
	}
	output, err := h.command(ctx, "container", "ls", "--all", "--no-trunc", "--filter", "label="+installationLabel+"="+r.InstallationID, "--filter", "label="+runLabel+"="+r.ID, "--format", "{{.ID}}")
	if err != nil {
		return "", false, err
	}
	ids := strings.Fields(string(output))
	if len(ids) > 1 {
		return "", false, errors.New("multiple containers claim one lifecycle identity")
	}
	if r.ContainerID != "" {
		byID, err := h.command(ctx, "container", "ls", "--all", "--no-trunc", "--filter", "id="+r.ContainerID, "--format", "{{.ID}}")
		if err != nil {
			return "", false, err
		}
		exact := strings.Fields(string(byID))
		if len(exact) > 1 || (len(exact) == 1 && exact[0] != r.ContainerID) {
			return "", false, errors.New("container ID reconciliation is ambiguous")
		}
		if len(exact) != len(ids) || (len(ids) == 1 && ids[0] != r.ContainerID) {
			return "", false, errors.New("container labels or ID differ from lifecycle record")
		}
	}
	if len(ids) == 0 {
		return "", false, nil
	}
	id := ids[0]
	if !fullContainerID.MatchString(id) {
		return "", false, errors.New("container listing did not return a full ID")
	}
	inspection, err := h.command(ctx, "container", "inspect", "--format", "{{json .}}", id)
	if err != nil {
		return "", false, err
	}
	var found struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(inspection, &found) != nil || found.ID != id || found.Name != "/"+r.ContainerName || found.Image != r.RuntimeImage || found.Config.Labels[installationLabel] != r.InstallationID || found.Config.Labels[runLabel] != r.ID {
		return "", false, fmt.Errorf("container identity does not match owned lifecycle %s", r.ID)
	}
	return id, true, nil
}
