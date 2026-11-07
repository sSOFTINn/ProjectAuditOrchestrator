package prompt

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type observedReader struct {
	io.Reader
	started chan struct{}
}

func (r observedReader) Read(p []byte) (int, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	return r.Reader.Read(p)
}

func TestLineCancellationDoesNotWaitForOpenInput(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Line(ctx, bufio.NewReader(observedReader{r, started}))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("input read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation waited for a newline or EOF")
	}
}

func TestLinePreservesBufferedPromptsAndRejectsCancelledAnswer(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("first\nsecond\r\nlast"))
	for _, want := range []string{"first\n", "second\r\n", "last"} {
		line, err := Line(context.Background(), r)
		if line != want || err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("line=%q error=%v want=%q", line, err, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	line, err := Line(ctx, bufio.NewReader(strings.NewReader("APPROVE exact\n")))
	if line != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled answer was returned: %q %v", line, err)
	}
}

type cancellingReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r cancellingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}

func TestLineCancellationWinsOverAnAvailableApproval(t *testing.T) {
	for _, answer := range []string{"APPROVE exact AS Owner\n", "RECOVER exact\n"} {
		ctx, cancel := context.WithCancel(context.Background())
		input := bufio.NewReader(cancellingReader{strings.NewReader(answer), cancel})
		line, err := Line(ctx, input)
		cancel()
		if line != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("answer was accepted with cancellation: %q %v", line, err)
		}
	}
}
