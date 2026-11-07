package recovery

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

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
