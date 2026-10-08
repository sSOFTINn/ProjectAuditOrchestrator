package localaudit

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func TestProgressStagesHeartbeatAndStopAreSafe(t *testing.T) {
	var out bytes.Buffer
	p := startProgress(&out, "scancode", 4, 9, time.Hour)
	p.stage(runner.StageState)
	p.heartbeat(time.Now().Add(12 * time.Second))
	p.stage(runner.StageLaunch)
	p.finish(runner.ToolExecution{Status: runner.Failed, DiagnosticCode: "SCANNER_FAILED"})
	before := out.String()
	p.stage(runner.StagePersist)
	p.heartbeat(time.Now())
	if out.String() != before {
		t.Fatal("late progress after finish")
	}
	for _, s := range []string{"[4/9]", "ScanCode", "цілісність", "12 с", "сканування", "SCANNER_FAILED"} {
		if !strings.Contains(before, s) {
			t.Fatalf("missing %q in %s", s, before)
		}
	}
	var unsafe bytes.Buffer
	bad := startProgress(&unsafe, "SECRET\x1b[31m", 1, 1, time.Hour)
	bad.stage(runner.Stage("PRIVATE_STAGE"))
	bad.finish(runner.ToolExecution{Status: "PRIVATE_STATUS", DiagnosticCode: "PRIVATE_CODE"})
	if strings.Contains(unsafe.String(), "PRIVATE") || strings.Contains(unsafe.String(), "SECRET") || strings.ContainsRune(unsafe.String(), 27) {
		t.Fatal("untrusted text in progress")
	}
}

type heartbeatSink struct {
	mu     sync.Mutex
	data   bytes.Buffer
	notice chan struct{}
	once   sync.Once
}

func (s *heartbeatSink) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Contains(b, []byte("очікуємо завершення")) {
		s.once.Do(func() { close(s.notice) })
	}
	return s.data.Write(b)
}
func (s *heartbeatSink) text() string { s.mu.Lock(); defer s.mu.Unlock(); return s.data.String() }
func TestPeriodicProgressJoinsBeforeNextOutput(t *testing.T) {
	sink := &heartbeatSink{notice: make(chan struct{})}
	p := startProgress(sink, "scancode", 1, 1, time.Millisecond)
	select {
	case <-sink.notice:
	case <-time.After(2 * time.Second):
		p.finish(runner.ToolExecution{Status: runner.Failed})
		t.Fatal("heartbeat absent")
	}
	p.finish(runner.ToolExecution{Status: runner.Succeeded})
	before := sink.text()
	time.Sleep(5 * time.Millisecond)
	if sink.text() != before {
		t.Fatal("heartbeat outlived run")
	}
}
