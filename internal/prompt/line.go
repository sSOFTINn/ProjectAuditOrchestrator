// Package prompt provides cancellation-aware reads for local CLI prompts.
package prompt

import (
	"bufio"
	"context"
)

// Line reads one line from a caller-owned, bounded buffered reader. It preserves
// buffered input for later prompts. Cancellation returns without closing stdin;
// the command must then stop reading. Embedded callers should close their input
// after cancellation to release the single possibly blocked reader goroutine.
func Line(ctx context.Context, input *bufio.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	type result struct {
		line string
		err  error
	}
	ready := make(chan result, 1)
	go func() {
		line, err := input.ReadString('\n')
		ready <- result{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case read := <-ready:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return read.line, read.err
	}
}
