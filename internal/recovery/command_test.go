package recovery

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

type recoveryPromptReader struct {
	io.Reader
	started chan struct{}
}

func (r recoveryPromptReader) Read(p []byte) (int, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	return r.Reader.Read(p)
}

func TestRecoveryCancellationWithOpenInputNeverApplies(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}, 1), make(chan int, 1)
	var out, errs bytes.Buffer
	calls := []bool{}
	fake := func(_ context.Context, _, id string, apply bool) (runner.RecoveryResult, error) {
		calls = append(calls, apply)
		return runner.RecoveryResult{RunID: id, Status: "PENDING"}, nil
	}
	go func() {
		done <- command(ctx, []string{"--state", "synthetic", "--run", strings.Repeat("a", 32), "--apply"}, recoveryPromptReader{r, started}, &out, &errs, fake)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not reach confirmation")
	}
	cancel()
	select {
	case code := <-done:
		if code != 5 || len(calls) != 1 || calls[0] || !strings.Contains(errs.String(), "RECOVERY_NOT_CONFIRMED") {
			t.Fatalf("cancelled recovery mutated or failed to refuse: code=%d calls=%v stderr=%s", code, calls, errs.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recovery waited for stdin after cancellation")
	}
}

func TestRecoveryNeverAppliesWithoutExactConfirmation(t *testing.T) {
	for _, confirmation := range []string{"", "yes\n", "RECOVER other\n", "RECOVER " + strings.Repeat("a", 32) + "\n"} {
		calls := []bool{}
		fake := func(_ context.Context, state, id string, apply bool) (runner.RecoveryResult, error) {
			calls = append(calls, apply)
			return runner.RecoveryResult{RunID: id, Status: "PENDING"}, nil
		}
		var out, errs bytes.Buffer
		code := command(context.Background(), []string{"--state", "synthetic", "--run", strings.Repeat("a", 32), "--apply"}, strings.NewReader(confirmation), &out, &errs, fake)
		want := confirmation == "RECOVER "+strings.Repeat("a", 32)+"\n"
		if want {
			if code != 0 || len(calls) != 2 || !calls[1] {
				t.Fatalf("confirmed recovery failed: %d %v", code, calls)
			}
		} else if code != 5 || len(calls) != 1 {
			t.Fatalf("unconfirmed mutation: %d %v", code, calls)
		}
	}
}

func TestRecoveryPreviewIsReadOnly(t *testing.T) {
	var out, errs bytes.Buffer
	code := command(context.Background(), []string{"--state", "synthetic", "--run", "record", "--json"}, strings.NewReader("RECOVER record\n"), &out, &errs, func(_ context.Context, _, id string, apply bool) (runner.RecoveryResult, error) {
		if apply {
			t.Fatal("preview applied cleanup")
		}
		return runner.RecoveryResult{RunID: id, Status: "PENDING"}, nil
	})
	if code != 0 || !strings.Contains(out.String(), `"status":"PENDING"`) {
		t.Fatalf("preview failed: %d %s", code, errs.String())
	}
}
