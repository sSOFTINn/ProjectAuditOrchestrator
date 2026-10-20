package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/detect"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/localaudit"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

const (
	exitOK         = 0
	exitUsage      = 2
	exitIncomplete = 4
	exitBlocked    = 5
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(exitUsage)
	}
	var code int
	switch os.Args[1] {
	case "help", "--help", "-h":
		usage(os.Stdout)
		code = exitOK
	case "version":
		fmt.Println(buildinfo.Version)
		code = exitOK
	case "doctor":
		code = doctor()
	case "inspect":
		code = inspect(os.Args[2:])
	case "plan":
		code = dryPlan(os.Args[2:])
	case "audit":
		code = audit(os.Args[2:])
	default:
		usage(os.Stderr)
		code = exitUsage
	}
	os.Exit(code)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `PAO — локальний аудит із попереднім переглядом і точним підтвердженням.

Використання:
  pao --help
  pao version
  pao doctor
  pao inspect --target PATH
  pao plan --target PATH --profile fast --dry-run
  pao audit --config FILE --profile secrets [--execute]

Команди:
  version  Версія PAO.
  doctor   Ідентичність PAO; не перевірка готовності Docker чи сканерів.
  inspect  Читання структури цілі без запуску її коду або сканерів.
  plan     Попередній план без сканерів; --dry-run обов'язковий.
           Профілі цього окремого режиму: fast, mvp.
  audit    Перегляд аудиту з приватним JSON налаштувань.
           --execute додатково вимагає поточну фразу RUN <audit-id> <plan-digest>.

Профілі audit:
  secrets       Gitleaks: пошук секретів у поточних файлах.
  fast          Trivy: вразливості залежностей.
  deep-sca      Syft, Grype, OSV-Scanner: склад і вразливості залежностей.
  license       ScanCode, REUSE: ліцензійні спостереження.
  sast          Opengrep: статичний аналіз.
  ci-security   zizmor: налаштування CI.
  sbom-quality  Syft, sbomqs: інформаційна оцінка SBOM.
  mvp           Усі адаптери з перевіркою застосовності й готовності.

Початок: перевірте пакет, прочитайте START_HERE.uk.md і використайте
синтетичну ціль. Для першого налаштованого аудиту достатньо профілю secrets;
сканер Linux AMD64 та погоджена Docker Desktop Linux VM готуються окремо.
FILE — абсолютний шлях або коротке ім'я у приватній папці PAO/config.
Прапорці команди: pao audit --help, pao inspect --help, pao plan --help.

audit: код 0 — лише preview/довідка; 3 — помилка конфігурації чи I/O;
4 — потрібен розгляд/неповне виконання; 5 — відмова підтвердження або політики.
PAO не надає автоматичного висновку про безпеку чи юридичну відповідність.
Сумісний режим лише читання: pao audit --target PATH --no-adapters.`)
}

func audit(args []string) int {
	// Preserve the existing explicitly non-executing inspection command only.
	for _, arg := range args {
		if arg == "--no-adapters" || strings.HasPrefix(arg, "--no-adapters=") {
			return noAdapters(args)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return localaudit.Command(ctx, args, os.Stdin, os.Stdout, os.Stderr)
}

func writeJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func doctor() int {
	result := map[string]any{"version": buildinfo.Version, "revision": buildinfo.Revision, "source_state": buildinfo.SourceState, "go": runtime.Version(), "network": "denied-by-default", "target_write": false, "target_execution": false, "runner": "verification-required-per-audit"}
	producer, err := buildinfo.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PAO executable identity is unavailable")
		return exitBlocked
	}
	result["producer"] = producer
	if err := writeJSON(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	return exitOK
}

func inspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("target", "", "target directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "inspect requires --target PATH")
		return exitUsage
	}
	s, err := target.SnapshotRoot(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	result := struct {
		Snapshot target.Snapshot `json:"snapshot"`
		Detected detect.Result   `json:"detected"`
	}{s, detect.Detect(s)}
	if err := writeJSON(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	if !s.Complete {
		return exitIncomplete
	}
	return exitOK
}

func dryPlan(args []string) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("target", "", "target directory")
	profile := fs.String("profile", "", "explicit audit profile (fast or mvp for legacy dry plan)")
	dryRun := fs.Bool("dry-run", false, "do not execute adapters")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *path == "" || !*dryRun || (*profile != "fast" && *profile != "mvp") || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "plan requires --target PATH --profile NAME --dry-run")
		return exitUsage
	}
	s, err := target.SnapshotRoot(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	p := plan.Build(s, *profile, true)
	if err := writeJSON(p); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	if !s.Complete {
		return exitIncomplete
	}
	return exitOK
}

func noAdapters(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("target", "", "target directory")
	noAdapter := fs.Bool("no-adapters", false, "plan/inspect only")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *path == "" || !*noAdapter {
		fmt.Fprintln(os.Stderr, "audit requires --target PATH --no-adapters")
		return exitUsage
	}
	s, err := target.SnapshotRoot(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	result := map[string]any{"status": "INCOMPLETE", "reason": "adapter execution disabled", "snapshot": s, "plan": plan.Build(s, "fast", true)}
	if err := writeJSON(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	return exitIncomplete
}
