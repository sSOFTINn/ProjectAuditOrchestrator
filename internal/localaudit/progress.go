package localaudit

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

type progressDisplay struct {
	mu                    sync.Mutex
	output                io.Writer
	name                  string
	ordinal, total        int
	current               runner.Stage
	started, stageStarted time.Time
	stopped               bool
	stop, done            chan struct{}
}

func scannerLabel(id string) string {
	switch id {
	case "syft":
		return "Syft"
	case "sbomqs":
		return "sbomqs"
	case "grype":
		return "Grype"
	case "osv-scanner":
		return "OSV-Scanner"
	case "scancode":
		return "ScanCode"
	case "reuse":
		return "REUSE"
	case "trivy":
		return "Trivy"
	case "gitleaks":
		return "Gitleaks"
	case "opengrep":
		return "Opengrep"
	case "zizmor":
		return "zizmor"
	default:
		return "Інструмент"
	}
}

func startProgress(out io.Writer, id string, ordinal, total int, interval time.Duration) *progressDisplay {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	now := time.Now()
	p := &progressDisplay{output: out, name: scannerLabel(id), ordinal: ordinal, total: total, started: now, stageStarted: now, stop: make(chan struct{}), done: make(chan struct{})}
	p.stage(runner.StageValidate)
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case now := <-ticker.C:
				p.heartbeat(now)
			}
		}
	}()
	return p
}
func (p *progressDisplay) stage(s runner.Stage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	if p.current == s {
		return
	}
	p.current = s
	p.stageStarted = time.Now()
	fmt.Fprintf(p.output, "[%d/%d] %s: %s.\n", p.ordinal, p.total, p.name, runner.StageMessage(s))
}
func (p *progressDisplay) heartbeat(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	seconds := int(now.Sub(p.stageStarted).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	fmt.Fprintf(p.output, "[%d/%d] %s: %s — %d с; очікуємо завершення.\n", p.ordinal, p.total, p.name, runner.StageMessage(p.current), seconds)
}
func (p *progressDisplay) finish(e runner.ToolExecution) {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.stop)
	status := e.Status
	switch status {
	case runner.Succeeded, runner.NoFindings, runner.Partial, runner.Failed, runner.TimedOut, runner.PolicyBlocked, runner.Unavailable, runner.Unsupported:
	default:
		status = "INCOMPLETE"
	}
	fmt.Fprintf(p.output, "[%d/%d] %s: %s (%d с).\n", p.ordinal, p.total, p.name, status, int(time.Since(p.started).Seconds()))
	if runner.KnownDiagnosticCode(e.DiagnosticCode) {
		fmt.Fprintf(p.output, "  %s [%s]\n", runner.DiagnosticMessage(e.DiagnosticCode), e.DiagnosticCode)
	} else if status != runner.Succeeded && status != runner.NoFindings {
		fmt.Fprintln(p.output, runner.DiagnosticMessage(""))
	}
	if len(e.Diagnostics) > 0 {
		fmt.Fprintln(p.output, "  Докладна діагностика збережена приватно: див. diagnostics у run-record.json.")
	}
	p.mu.Unlock()
	<-p.done // No late heartbeat or concurrent write can leak into the next scanner.
}
