// pao-local-audit is a compatibility entry point for the confirmed configuration workflow.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/localaudit"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(localaudit.Command(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
