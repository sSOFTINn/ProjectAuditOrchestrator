package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func syntheticJournal(t *testing.T) *installation.Store {
	t.Helper()
	store, err := installation.Initialize(filepath.Join(t.TempDir(), "private-journal"))
	if err != nil {
		t.Fatal(err)
	}
	for i, status := range []string{"PENDING", "OBSERVED", "VERIFIED_ABSENT"} {
		id := strings.Repeat(string(rune('a'+i)), 32)
		stamp := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
		run := installation.Run{Version: installation.RunVersion, ID: id, InstallationID: store.ID(), AuditID: "private-audit-marker", ContainerName: "private-container-marker", Endpoint: "npipe:////./pipe/dockerDesktopLinuxEngine", RuntimeImage: "sha256:" + strings.Repeat("a", 64), DockerPath: filepath.Join(store.Root(), "private-docker-marker"), DockerSHA256: "sha256:" + strings.Repeat("b", 64), Status: status, CreatedAt: stamp, UpdatedAt: stamp}
		if status != "PENDING" {
			run.ContainerID = strings.Repeat("d", 64)
		}
		// Multiple pending records model retained historical state. The real
		// Begin API correctly refuses a second launch while one is pending.
		jsonFile(t, filepath.Join(store.Root(), "runs", id+".json"), run)
	}
	return store
}

func journalCheck(t *testing.T, result Result) Check {
	t.Helper()
	for _, check := range result.Checks {
		if check.ID == "installation.journal" {
			return check
		}
	}
	t.Fatal("installation journal check missing")
	return Check{}
}

func TestPendingJournalIDsAreValidatedReadOnlyAndReleaseLease(t *testing.T) {
	store := syntheticJournal(t)
	before := treeBytes(t, store.Root())
	got, err := pendingRunIDs(context.Background(), store.Root())
	want := []string{strings.Repeat("a", 32), strings.Repeat("b", 32)}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("pending identity inventory: %v, %v", got, err)
	}
	if !reflect.DeepEqual(before, treeBytes(t, store.Root())) {
		t.Fatal("journal inspection changed state")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lease, err := store.Lock(ctx, true)
	if err != nil {
		t.Fatalf("read-only inspection retained its shared lease: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPendingJournalErrorsReturnNoPartialIDsOrPrivateDetails(t *testing.T) {
	for _, name := range []string{"corrupt-record", "foreign-installation", "record-id-mismatch", "busy", "cancelled", "missing"} {
		t.Run(name, func(t *testing.T) {
			store := syntheticJournal(t)
			root := store.Root()
			ctx := context.Background()
			badPath := filepath.Join(root, "runs", strings.Repeat("f", 32)+".json")
			switch name {
			case "corrupt-record":
				write(t, badPath, []byte("private-error-marker"))
			case "foreign-installation", "record-id-mismatch":
				run, err := store.Read(strings.Repeat("a", 32))
				if err != nil {
					t.Fatal(err)
				}
				if name == "foreign-installation" {
					run.ID, run.InstallationID = strings.Repeat("f", 32), strings.Repeat("0", 32)
				}
				jsonFile(t, badPath, run)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing":
				root = filepath.Join(root, "absent")
			}
			before := treeBytes(t, store.Root())
			var heldLease *installation.Lease
			if name == "busy" {
				var err error
				heldLease, err = store.Lock(context.Background(), true)
				if err != nil {
					t.Fatal(err)
				}
				defer heldLease.Close()
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			ids, err := pendingRunIDs(ctx, root)
			if err == nil || len(ids) != 0 {
				t.Fatalf("failed inventory exposed IDs or succeeded: %v, %v", ids, err)
			}
			if heldLease != nil {
				if err := heldLease.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, treeBytes(t, store.Root())) {
				t.Fatal("failed inspection changed journal state")
			}
			if name == "missing" {
				if _, err := os.Lstat(root); !os.IsNotExist(err) {
					t.Fatal("doctor created the missing state directory")
				}
			}
			path, _, d := fixture(t)
			d.pendingRuns = func(context.Context, string) ([]string, error) {
				// Even a faulty provider must not leak partial IDs with its error.
				return []string{strings.Repeat("a", 32)}, errors.New(root + ": private-error-marker")
			}
			d.runtime = func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error) {
				t.Fatal("unavailable journal reached runtime inspection")
				return runner.SandboxProperties{}, nil
			}
			result := inspect(context.Background(), path, "secrets", d)
			check := journalCheck(t, result)
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "SETUP_REQUIRED" || check.Status != "SETUP_REQUIRED" || len(check.PendingRunIDs) != 0 || bytes.Contains(raw, []byte("pending_run_ids")) || bytes.Contains(raw, []byte("private-error-marker")) || bytes.Contains(raw, []byte("private-journal")) {
				t.Fatalf("journal error was not safely summarized: %+v", check)
			}
		})
	}
}

func TestDoctorCommandShowsExactPendingIDsInJSONAndText(t *testing.T) {
	path, config, d := fixture(t)
	store := syntheticJournal(t)
	config.InstallationState = store.Root()
	jsonFile(t, path, config)
	d.pendingRuns = pendingRunIDs
	d.runtime = func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error) {
		t.Fatal("pending journal reached runtime inspection")
		return runner.SandboxProperties{}, nil
	}
	check := journalCheck(t, inspect(context.Background(), path, "secrets", d))
	want := []string{strings.Repeat("a", 32), strings.Repeat("b", 32)}
	if check.Status != "SETUP_REQUIRED" || !reflect.DeepEqual(check.PendingRunIDs, want) {
		t.Fatalf("missing actionable pending IDs: %+v", check)
	}
	beforeState, beforeFixture := treeBytes(t, store.Root()), treeBytes(t, filepath.Dir(filepath.Dir(path)))
	for _, asJSON := range []bool{false, true} {
		var output, errout bytes.Buffer
		args := []string{"--config", path, "--profile", "secrets"}
		if asJSON {
			args = append(args, "--json")
		}
		if code := Command(context.Background(), args, &output, &errout); code != 5 || errout.Len() != 0 {
			t.Fatalf("pending doctor command: exit=%d stderr=%q", code, errout.String())
		}
		text := output.String()
		for _, id := range want {
			if !strings.Contains(text, id) {
				t.Fatalf("pending ID absent from json=%t output", asJSON)
			}
		}
		if !strings.Contains(text, "pao recover --config FILE --run "+want[0]) || strings.Contains(text, "--apply") {
			t.Fatal("recovery guidance is not an exact read-only preview")
		}
		for _, private := range []string{"private-journal", "private-audit-marker", "private-container-marker", "private-docker-marker", "dockerDesktopLinuxEngine", config.Target, path} {
			if strings.Contains(text, private) {
				t.Fatalf("doctor exposed private state field %q", private)
			}
		}
		if asJSON {
			var result Result
			if err := json.Unmarshal(output.Bytes(), &result); err != nil || !reflect.DeepEqual(journalCheck(t, result).PendingRunIDs, want) {
				t.Fatalf("JSON pending IDs: %v", err)
			}
		}
	}
	if !reflect.DeepEqual(beforeState, treeBytes(t, store.Root())) || !reflect.DeepEqual(beforeFixture, treeBytes(t, filepath.Dir(filepath.Dir(path)))) {
		t.Fatal("doctor command changed state or target fixture")
	}
}
