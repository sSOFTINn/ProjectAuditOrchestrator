package runstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

func TestPlanLockIsCrashSafeAndResumable(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Build(target.Snapshot{TargetID: "sha256:target"}, "fast", true)
	created, err := store.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := store.Resume(p.PlanDigest)
	if err != nil || resumed.LockPath != created.LockPath || resumed.Plan.PlanDigest != p.PlanDigest {
		t.Fatalf("run could not resume safely: %#v %v", resumed, err)
	}
	if _, err := os.Stat(filepath.Join(created.Directory, lockName)); err != nil {
		t.Fatal(err)
	}
}

func TestPlanLockRejectsTampering(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Build(target.Snapshot{TargetID: "sha256:target"}, "fast", true)
	created, err := store.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(created.LockPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created.LockPath, []byte(`{"version":"pao.dev/plan/v1alpha1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resume(p.PlanDigest); err == nil {
		t.Fatal("tampered lock was accepted")
	}
}
