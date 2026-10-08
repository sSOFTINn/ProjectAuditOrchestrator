package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
		usage()
		os.Exit(exitUsage)
	}
	var code int
	switch os.Args[1] {
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
		usage()
		code = exitUsage
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pao version | doctor | inspect --target PATH | plan --target PATH --profile NAME --dry-run | audit --config FILE --profile NAME [--execute] | audit --target PATH --no-adapters")
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
	if err := fs.Parse(args); err != nil || *path == "" {
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
	if err := fs.Parse(args); err != nil || *path == "" || !*dryRun || (*profile != "fast" && *profile != "mvp") || fs.NArg() != 0 {
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
	if err := fs.Parse(args); err != nil || *path == "" || !*noAdapter {
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
