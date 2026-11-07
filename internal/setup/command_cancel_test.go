package setup

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
)

type setupPromptReader struct {
	io.Reader
	started chan struct{}
}

func (r setupPromptReader) Read(p []byte) (int, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	return r.Reader.Read(p)
}

func TestSetupCancellationBeforePreparationLeavesRootAbsent(t *testing.T) {
	pkg, recipes := recipeFixture(t)
	oldRecipe, oldProbe, oldSandbox := buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256
	buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = recipes.Digest, strings.Repeat("a", 64), strings.Repeat("b", 64)
	t.Cleanup(func() {
		buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = oldRecipe, oldProbe, oldSandbox
	})
	for _, which := range []string{"target", "prepare"} {
		t.Run(which, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-created")
			args := []string{"--root", root, "--package-root", pkg, "--apply"}
			if which == "prepare" {
				args = append(args, "--target", t.TempDir())
			}
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, done := make(chan struct{}, 1), make(chan int, 1)
			var out, errs bytes.Buffer
			go func() { done <- Command(ctx, args, setupPromptReader{r, started}, &out, &errs) }()
			select {
			case <-started:
			case code := <-done:
				t.Fatalf("setup exited before prompt: %d %s", code, errs.String())
			case <-time.After(5 * time.Second):
				t.Fatal("setup did not reach input prompt")
			}
			cancel()
			select {
			case code := <-done:
				if code != 2 {
					t.Fatalf("unexpected cancelled setup exit: %d %s", code, errs.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("setup waited for stdin after cancellation")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("unconfirmed setup changed installation: %v", err)
			}
		})
	}
}

func TestSetupApprovalCancellationWithOpenInputIsNotApproval(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}, 1), make(chan bool, 1)
	var out bytes.Buffer
	go func() {
		done <- confirm(ctx, bufio.NewReader(setupPromptReader{r, started}), &out, "APPROVE sha256:exact AS Owner")
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("approval prompt did not read input")
	}
	cancel()
	select {
	case approved := <-done:
		if approved {
			t.Fatal("cancellation created approval")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("approval waited for stdin after cancellation")
	}
}
