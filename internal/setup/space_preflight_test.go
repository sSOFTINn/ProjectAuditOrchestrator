package setup

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInsufficientSpaceFailsBeforeCreatingInstallation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	_, err := apply(context.Background(), options{}, Recipes{}, Plan{Root: root, MinimumFreeBytes: math.MaxInt64}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "free bytes") {
		t.Fatalf("expected space diagnostic, got %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("insufficient-space check created installation")
	}
}
