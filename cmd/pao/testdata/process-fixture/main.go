// This native test helper never launches a scanner. It exposes report rebuilding
// and controlled context cancellation to the process-level CLI contract tests.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditresult"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/localaudit"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/plan"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "cancel":
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		input, writer := io.Pipe()
		defer input.Close()
		defer writer.Close()
		go func() {
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if line == "cancel\n" {
				cancel()
			}
		}()
		os.Exit(localaudit.Command(ctx, os.Args[2:], input, os.Stdout, os.Stderr))
	case "rebuild":
		if len(os.Args) != 5 {
			os.Exit(2)
		}
		var lock plan.Plan
		var record runner.Record
		read(os.Args[3], &lock)
		read(os.Args[4], &record)
		catalog, err := toolchain.New(nil)
		if err != nil {
			panic(err)
		}
		result := auditresult.Build(os.Args[2], lock, record, catalog, false)
		if err = json.NewEncoder(os.Stdout).Encode(result.Portable()); err != nil {
			panic(err)
		}
	default:
		os.Exit(2)
	}
}

func read(path string, value any) {
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, value)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
