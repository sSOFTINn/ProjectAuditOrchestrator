// Package recovery exposes exact, operator-confirmed container recovery.
package recovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func Command(ctx context.Context, args []string, input io.Reader, output, errout io.Writer) int {
	return command(ctx, args, input, output, errout, runner.RecoverInstallationRun)
}

type recoverRun func(context.Context, string, string, bool) (runner.RecoveryResult, error)

func command(ctx context.Context, args []string, input io.Reader, output, errout io.Writer, recover recoverRun) int {
	fail := func(err error) int { fmt.Fprintf(errout, "PAO recovery: %v\n", err); return 3 }
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(errout)
	config := fs.String("config", "", "private audit config with installation_state")
	state := fs.String("state", "", "private installation state (for interrupted setup before config exists)")
	run := fs.String("run", "", "exact pending lifecycle ID printed by PAO")
	apply := fs.Bool("apply", false, "preview then require RECOVER <run-id> before exact cleanup")
	jsonOutput := fs.Bool("json", false, "JSON result; confirmation remains explicit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if fs.NArg() != 0 || *run == "" || (*config == "") == (*state == "") {
		return fail(errors.New("use --run ID and exactly one of --config FILE or --state PATH"))
	}
	root := *state
	if *config != "" {
		path, err := auditconfig.Resolve(*config)
		if err != nil {
			return fail(err)
		}
		if err := auditconfig.CheckPath(path, false); err != nil {
			return fail(err)
		}
		f, err := os.Open(path)
		if err != nil {
			return fail(err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, auditconfig.MaxBytes+1))
		closeErr := f.Close()
		if err = errors.Join(readErr, closeErr); err != nil {
			return fail(err)
		}
		c, err := auditconfig.Decode(raw)
		if err != nil {
			return fail(err)
		}
		if c.Version != auditconfig.InstallationVersion || c.InstallationState == "" {
			return fail(errors.New("recovery requires configuration v3 or explicit --state"))
		}
		root = c.InstallationState
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	preview, err := recover(probeCtx, root, *run, false)
	cancel()
	if err != nil {
		return fail(err)
	}
	if *apply {
		fmt.Fprintf(output, "Run %s; recorded state %s; container present=%t. Only this verified PAO container may be removed; evidence is retained.\n", *run, preview.Status, preview.ContainerPresent)
		phrase := "RECOVER " + *run
		fmt.Fprintf(output, "Confirm: %s\n> ", phrase)
		line, err := bufio.NewReader(io.LimitReader(input, 256)).ReadString('\n')
		if err != nil || line != phrase+"\n" && line != phrase+"\r\n" {
			fmt.Fprintln(errout, "RECOVERY_NOT_CONFIRMED")
			return 5
		}
		if err := ctx.Err(); err != nil {
			return 5
		}
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		preview, err = recover(runCtx, root, *run, true)
		cancel()
		if err != nil {
			return fail(err)
		}
	}
	if *jsonOutput {
		if err := json.NewEncoder(output).Encode(preview); err != nil {
			return fail(err)
		}
	} else {
		fmt.Fprintf(output, "%s: run=%s container_present=%t changed=%t\n", preview.Status, preview.RunID, preview.ContainerPresent, preview.Changed)
	}
	return 0
}
