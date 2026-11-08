package installation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, e := Initialize(filepath.Join(t.TempDir(), "installation"))
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestPendingSurvivesReopenAndBlocksNewLaunch(t *testing.T) {
	s := newStore(t)
	l, e := s.Lock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	r, e := l.Begin("audit-1", "pao-synthetic", "npipe:////./pipe/dockerDesktopLinuxEngine", "sha256:"+strings.Repeat("a", 64), filepath.Join(t.TempDir(), "docker"), "sha256:"+strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
	if e = CheckReady(s.Root()); e == nil || !strings.Contains(e.Error(), r.ID) {
		t.Fatalf("pending run was forgotten: %v", e)
	}
	s, e = Open(s.Root())
	if e != nil {
		t.Fatal(e)
	}
	l, e = s.Lock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if _, e = l.Begin("audit-2", "pao-second", r.Endpoint, r.RuntimeImage, r.DockerPath, r.DockerSHA256); e == nil {
		t.Fatal("concurrent pending run accepted")
	}
	r, e = l.Update(r, strings.Repeat("c", 64), "OBSERVED")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = l.Update(r, strings.Repeat("d", 64), "VERIFIED_ABSENT"); e == nil {
		t.Fatal("container ID substitution accepted")
	}
	r, e = l.Update(r, r.ContainerID, "VERIFIED_ABSENT")
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
	if e = CheckReady(s.Root()); e != nil {
		t.Fatal(e)
	}
	stored, e := s.Read(r.ID)
	if e != nil || stored.Status != "VERIFIED_ABSENT" {
		t.Fatalf("history disappeared: %v", e)
	}
}

func TestLeaseExcludesOtherWriters(t *testing.T) {
	s := newStore(t)
	a, e := s.Lock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if b, e := s.Lock(ctx, true); e == nil {
		b.Close()
		t.Fatal("second writer acquired lease")
	}
}

func TestReadOnlyOpenAndOrphanedTransaction(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, e := Open(missing); e == nil {
		t.Fatal("missing installation accepted")
	}
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("read-only open created state")
	}
	s := newStore(t)
	if e := os.WriteFile(filepath.Join(s.Root(), "transactions", "interrupted.next"), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckReady(s.Root()); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(s.Root(), "runs", strings.Repeat("a", 32)+".json"), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckReady(s.Root()); e == nil {
		t.Fatal("corrupt authoritative journal accepted")
	}
}

func TestRecoveryPathCannotEscape(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{"../installation", "", strings.Repeat("A", 32), "a.json"} {
		if _, e := s.Read(id); e == nil {
			t.Fatal("invalid run ID accepted")
		}
	}
}
