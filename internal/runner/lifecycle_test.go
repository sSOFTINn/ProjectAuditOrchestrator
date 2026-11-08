package runner

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

type lifecycleEngine struct {
	t                                    *testing.T
	store                                *installation.Store
	present                              bool
	foreign                              bool
	createFails                          bool
	createCalls, startCalls, removeCalls int
	record                               installation.Run
}

func (e *lifecycleEngine) command(_ context.Context, _ string, args ...string) ([]byte, error) {
	args = args[2:]
	if args[0] == "create" {
		e.createCalls++
		pending, err := e.store.Pending()
		if err != nil || len(pending) != 1 {
			e.t.Fatalf("container created before durable pending record: %v", err)
		}
		e.record = pending[0]
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--label pao.installation="+e.record.InstallationID) || !strings.Contains(joined, "--label pao.run="+e.record.ID) {
			e.t.Fatal("missing lifecycle labels")
		}
		e.present = true
		if e.createFails {
			return nil, errors.New("synthetic lost create response")
		}
		return []byte(strings.Repeat("c", 64)), nil
	}
	if args[0] == "container" && args[1] == "ls" {
		if e.present {
			return []byte(strings.Repeat("c", 64)), nil
		}
		return nil, nil
	}
	if args[0] == "container" && args[1] == "inspect" {
		labels := map[string]string{"pao.installation": e.record.InstallationID, "pao.run": e.record.ID}
		if e.foreign {
			labels["pao.run"] = "foreign"
		}
		return json.Marshal(map[string]any{"Id": strings.Repeat("c", 64), "Name": "/" + e.record.ContainerName, "Image": e.record.RuntimeImage, "Config": map[string]any{"Labels": labels}})
	}
	if args[0] == "rm" {
		if args[2] != strings.Repeat("c", 64) {
			e.t.Fatal("cleanup did not use full verified ID")
		}
		e.removeCalls++
		e.present = false
		return nil, nil
	}
	return nil, errors.New("unexpected synthetic control command")
}

func lifecycleFixture(t *testing.T) (DockerHost, *lifecycleEngine) {
	s, err := installation.Initialize(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	e := &lifecycleEngine{t: t, store: s}
	h := DockerHost{DockerPath: filepath.Join(t.TempDir(), "docker"), DockerSHA256: "sha256:" + strings.Repeat("d", 64), RuntimeImage: fixtureImage, RuntimeApproval: fixtureApproval(), InstallationState: s.Root(), AuditID: "synthetic-audit", runDocker: e.command, connection: func() (dockerConnection, error) {
		return dockerConnection{endpoint: dockerDesktopLinuxEndpoint, user: "65532:65532"}, nil
	}}
	h.runCaptured = func(_ context.Context, _ string, args ...string) (commandOutput, error) {
		e.startCalls++
		if strings.Join(args[2:], " ") != "start --attach "+strings.Repeat("c", 64) {
			t.Fatal("unexpected start command")
		}
		pending, err := s.Pending()
		if err != nil || len(pending) != 1 || pending[0].ContainerID != strings.Repeat("c", 64) || pending[0].Status != "OBSERVED" {
			t.Fatal("scanner started before full ID was durable")
		}
		return commandOutput{stdout: []byte("synthetic output")}, nil
	}
	return h, e
}

func TestTrackedLaunchPersistsIdentityBeforeStart(t *testing.T) {
	h, e := lifecycleFixture(t)
	_, err := h.launchTrackedCommand(context.Background(), ExecutionSpec{ContainerName: "pao-own"}, []string{"run", "--rm", fixtureImage})
	if err != nil {
		t.Fatal(err)
	}
	if e.createCalls != 1 || e.startCalls != 1 || e.removeCalls != 1 {
		t.Fatalf("incorrect lifecycle counts: %+v", e)
	}
	if err := installation.CheckReady(e.store.Root()); err != nil {
		t.Fatal(err)
	}
	r, err := e.store.Read(e.record.ID)
	if err != nil || r.Status != "VERIFIED_ABSENT" {
		t.Fatal("completed lifecycle not retained")
	}
}

func TestLostCreateResponseSurvivesRestartAndRequiresRecovery(t *testing.T) {
	h, e := lifecycleFixture(t)
	e.createFails = true
	_, err := h.launchTrackedCommand(context.Background(), ExecutionSpec{ContainerName: "pao-own"}, []string{"run", "--rm", fixtureImage})
	var pending *UnconfirmedContainerCleanupError
	if !errors.As(err, &pending) || e.startCalls != 0 || e.removeCalls != 0 {
		t.Fatal("ambiguous create must remain pending")
	}
	reopened, err := installation.Open(e.store.Root())
	if err != nil {
		t.Fatal(err)
	}
	r, err := reopened.Read(e.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := reopened.Lock(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := ReconcileLifecycle(context.Background(), h, l, r, false); err != nil {
		t.Fatal(err)
	}
	if e.removeCalls != 0 {
		t.Fatal("preview removed a container")
	}
	r, err = ReconcileLifecycle(context.Background(), h, l, r, true)
	if err != nil || r.Status != "VERIFIED_ABSENT" || e.removeCalls != 1 {
		t.Fatalf("recovery failed: %v", err)
	}
}

func TestRecoveryRefusesForeignIdentity(t *testing.T) {
	h, e := lifecycleFixture(t)
	e.createFails = true
	_, _ = h.launchTrackedCommand(context.Background(), ExecutionSpec{ContainerName: "pao-own"}, []string{"run", "--rm", fixtureImage})
	e.foreign = true
	l, err := e.store.Lock(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := ReconcileLifecycle(context.Background(), h, l, e.record, true); err == nil || e.removeCalls != 0 {
		t.Fatal("foreign container was accepted for cleanup")
	}
}

func TestFinalAdmissionRunsAfterCreateBeforeStart(t *testing.T) {
	h, e := lifecycleFixture(t)
	_, err := h.launchTrackedCommand(context.Background(), ExecutionSpec{ContainerName: "pao-own", launchAdmission: func() error { return errors.New("synthetic expired admission") }}, []string{"run", "--rm", fixtureImage})
	if err == nil || e.createCalls != 1 || e.startCalls != 0 || e.removeCalls != 1 {
		t.Fatalf("late refusal failed to clean before start: %v", err)
	}
	if err := installation.CheckReady(e.store.Root()); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationDeadlineProvesStartedContainerAndCleans(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "created-only", true: "running"}[started], func(t *testing.T) {
			h, engine := lifecycleFixture(t)
			h.preparation = &preparationAdmission{image: h.RuntimeImage, dockerDigest: h.DockerSHA256, createdAt: time.Now()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			capture := h.runCaptured
			h.runCaptured = func(ctx context.Context, path string, args ...string) (commandOutput, error) {
				if _, err := capture(ctx, path, args...); err != nil {
					t.Fatal(err)
				}
				cancel()
				return commandOutput{}, context.DeadlineExceeded
			}
			control := h.runDocker
			stateProbes := 0
			h.runDocker = func(ctx context.Context, path string, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "{{json .State}}") {
					stateProbes++
					if ctx.Err() != nil {
						t.Fatal("deadline interrupted the independent cleanup proof")
					}
					if started {
						return []byte(`{"Running":true,"StartedAt":"2026-11-07T14:00:00Z"}`), nil
					}
					return []byte(`{"Running":false,"StartedAt":"0001-01-01T00:00:00Z"}`), nil
				}
				return control(ctx, path, args...)
			}
			output, err := h.launchTrackedCommand(ctx, ExecutionSpec{ContainerName: "pao-own-timeout", Environment: map[string]string{"PAO_QUOTA_FIXTURE": "timeout"}}, []string{"run", "--rm", fixtureImage})
			if !errors.Is(err, context.DeadlineExceeded) || output.containerStarted != started || stateProbes != 1 || engine.removeCalls != 1 || output.lifecycleID != engine.record.ID {
				t.Fatalf("timeout/start/cleanup evidence lost: started=%t output=%+v err=%v probes=%d removals=%d", started, output, err, stateProbes, engine.removeCalls)
			}
			if err := installation.CheckReady(engine.store.Root()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
