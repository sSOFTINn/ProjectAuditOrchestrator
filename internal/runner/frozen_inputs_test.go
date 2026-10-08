package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func frozenTestDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func frozenWriteTestFile(t *testing.T, path string, content []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	// Test fixtures declare an exact mode independently of the host's umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return frozenTestDigest(content)
}

func frozenWriteTestJSON(t *testing.T, path string, value any) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return frozenWriteTestFile(t, path, content, 0o600)
}

func frozenFixture(t *testing.T) (ExecutionSpec, FrozenInputLimits, string) {
	t.Helper()
	root := t.TempDir()
	sources := filepath.Join(root, "sources")
	spec := ExecutionSpec{
		APIVersion:      "pao.dev/execution/v1alpha1",
		AdapterID:       "fixture",
		ToolID:          "fixture",
		ToolPath:        filepath.Join(sources, "tool", "scanner"),
		InputPath:       filepath.Join(sources, "input", "captured.json"),
		StatePath:       filepath.Join(sources, "state"),
		StateEntrypoint: "bin/entrypoint",
		DatabasePath:    filepath.Join(sources, "database"),
		RulePackPath:    filepath.Join(sources, "rules"),
		TargetRoot:      filepath.Join(root, "captured-target"),
		TemporaryDir:    filepath.Join(root, "outputs", "scanner"),
		TimeoutSeconds:  10,
		Sandbox:         strongSandbox(),
	}
	for _, directory := range []string{spec.TargetRoot, spec.TemporaryDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spec.ToolDigest = frozenWriteTestFile(t, spec.ToolPath, []byte("approved-tool"), 0o755)
	spec.InputDigest = frozenWriteTestFile(t, spec.InputPath, []byte(`{"bomFormat":"CycloneDX"}`), 0o600)
	stateFile := "bin/entrypoint"
	stateDigest := frozenWriteTestFile(t, filepath.Join(spec.StatePath, filepath.FromSlash(stateFile)), []byte("approved-state"), 0o755)
	spec.StateDigest = frozenWriteTestJSON(t, filepath.Join(spec.StatePath, preparedStateManifestName), preparedStateManifest{APIVersion: "pao.dev/prepared-state/v1alpha1", AdapterID: spec.AdapterID, Files: []preparedStateFile{{stateFile, strings.TrimPrefix(stateDigest, "sha256:")}}})
	databaseFile := "db/data.bin"
	databaseDigest := frozenWriteTestFile(t, filepath.Join(spec.DatabasePath, filepath.FromSlash(databaseFile)), []byte("approved-database"), 0o600)
	supportDigest := frozenWriteTestFile(t, filepath.Join(spec.DatabasePath, "support.txt"), []byte("approved-support"), 0o600)
	spec.DatabaseDigest = frozenWriteTestJSON(t, filepath.Join(spec.DatabasePath, databaseMetadataName), databaseMetadata{Schema: "pao.dev/toolchain-database-metadata/v1", Tool: spec.AdapterID, Files: []databaseFileHash{{databaseFile, strings.TrimPrefix(databaseDigest, "sha256:")}}, SupportingFiles: []databaseFileHash{{"support.txt", strings.TrimPrefix(supportDigest, "sha256:")}}})
	ruleDigest := frozenWriteTestFile(t, filepath.Join(spec.RulePackPath, "rules.yml"), []byte("approved-rules"), 0o600)
	spec.RulePackDigest = frozenWriteTestJSON(t, filepath.Join(spec.RulePackPath, inputCapsuleManifestName), inputCapsuleManifest{APIVersion: "pao.dev/input-capsule/v1alpha1", AdapterID: spec.AdapterID, Kind: "rule-pack", Files: []inputCapsuleFile{{"rules.yml", strings.TrimPrefix(ruleDigest, "sha256:")}}})
	spec.Arguments = []string{"scan", spec.TargetRoot, "--tool=" + spec.ToolPath, "--input=" + spec.InputPath, "--state=" + spec.StatePath, "--database=" + filepath.Join(spec.DatabasePath, "db", "data.bin"), "--rules=" + spec.RulePackPath}
	return spec, FrozenInputLimits{4096, 16384, 64, 4096}, sources
}

func assertFrozenFixture(t *testing.T, frozen ExecutionSpec) {
	t.Helper()
	for _, tc := range []struct {
		path, content string
	}{{frozen.ToolPath, "approved-tool"}, {frozen.InputPath, `{"bomFormat":"CycloneDX"}`}, {filepath.Join(frozen.StatePath, "bin", "entrypoint"), "approved-state"}, {filepath.Join(frozen.DatabasePath, "db", "data.bin"), "approved-database"}, {filepath.Join(frozen.DatabasePath, "support.txt"), "approved-support"}, {filepath.Join(frozen.RulePackPath, "rules.yml"), "approved-rules"}} {
		content, err := os.ReadFile(tc.path)
		if err != nil || string(content) != tc.content {
			t.Fatalf("unapproved bytes reached frozen invocation: %s %q %v", filepath.Base(tc.path), content, err)
		}
	}
	if err := VerifyPreparedState(frozen.StatePath, frozen.StateDigest, frozen.AdapterID); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabaseSnapshot(frozen.DatabasePath, frozen.DatabaseDigest, frozen.AdapterID); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInputCapsule(frozen.RulePackPath, frozen.RulePackDigest, frozen.AdapterID, "rule-pack"); err != nil {
		t.Fatal(err)
	}
}

func TestFreezeInputsOriginalUpdatesCannotChangeLaunchInputs(t *testing.T) {
	spec, limits, _ := frozenFixture(t)
	originalArguments := append([]string(nil), spec.Arguments...)
	frozen, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})
	for _, source := range []string{spec.ToolPath, spec.InputPath, filepath.Join(spec.StatePath, "bin", "entrypoint"), filepath.Join(spec.DatabasePath, "db", "data.bin"), filepath.Join(spec.RulePackPath, "rules.yml")} {
		if err := os.WriteFile(source, []byte("updated-original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// This is the launch barrier: consumers read the returned spec after every
	// original prerequisite has been updated by a cooperating writer.
	assertFrozenFixture(t, frozen)
	if frozen.TargetRoot != spec.TargetRoot || frozen.TemporaryDir != spec.TemporaryDir || filepath.Base(frozen.ToolPath) != filepath.Base(spec.ToolPath) {
		t.Fatal("already captured target, output or executable filename changed")
	}
	for index, argument := range frozen.Arguments {
		if strings.Contains(argument, spec.ToolPath) || strings.Contains(argument, spec.InputPath) || strings.Contains(argument, spec.StatePath) || strings.Contains(argument, spec.DatabasePath) || strings.Contains(argument, spec.RulePackPath) {
			t.Fatalf("original prerequisite remained in arguments: %q", argument)
		}
		if spec.Arguments[index] != originalArguments[index] {
			t.Fatal("freezing mutated caller arguments")
		}
	}
	base := filepath.Dir(filepath.Dir(frozen.ToolPath))
	if runtime.GOOS != "windows" {
		private, _ := os.Stat(base)
		if private.Mode().Perm() != 0o700 {
			t.Fatalf("private base is not owner-only: %v", private.Mode())
		}
		entrypoint, _ := os.Stat(filepath.Join(frozen.StatePath, "bin", "entrypoint"))
		if entrypoint.Mode().Perm() != 0o555 {
			t.Fatalf("state executable mode was not retained: %v", entrypoint.Mode())
		}
	}
}

func TestFreezeInputsAncestorSwapAfterValidationCannotChangeLaunch(t *testing.T) {
	spec, limits, sources := frozenFixture(t)
	frozen, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Rename(sources, sources+"-previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sources, 0o700); err != nil {
		t.Fatal(err)
	}
	frozenWriteTestFile(t, spec.ToolPath, []byte("replacement-tool"), 0o755)
	frozenWriteTestFile(t, spec.InputPath, []byte("replacement-input"), 0o600)
	for _, path := range []string{spec.StatePath, spec.DatabasePath, spec.RulePackPath} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	assertFrozenFixture(t, frozen)
}

func TestFreezeInputsBarrierUpdateBetweenCopyAndVerificationUsesOnlyApprovedBytes(t *testing.T) {
	spec, limits, _ := frozenFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	copyReached := make(chan struct{})
	updateComplete := make(chan struct{})
	type result struct {
		spec    ExecutionSpec
		cleanup func() error
		err     error
	}
	done := make(chan result, 1)
	go func() {
		frozen, cleanup, err := freezeInputs(ctx, spec, limits, func(source, _ string) error {
			if source != spec.ToolPath {
				return nil
			}
			close(copyReached)
			select {
			case <-updateComplete:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		done <- result{frozen, cleanup, err}
	}()
	select {
	case <-copyReached:
	case <-ctx.Done():
		t.Fatal("copy barrier was not reached")
	}
	updateErr := os.WriteFile(spec.ToolPath, []byte("updated-before-readback"), 0o600)
	close(updateComplete)
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	select {
	case observed := <-done:
		if observed.err != nil {
			t.Fatal(observed.err)
		}
		defer func() {
			if err := observed.cleanup(); err != nil {
				t.Error(err)
			}
		}()
		assertFrozenFixture(t, observed.spec)
	case <-ctx.Done():
		t.Fatal("freeze did not finish after update barrier")
	}
}

func TestFreezeInputsMutationBeforeCopyRefusesEveryPrerequisite(t *testing.T) {
	for _, kind := range []string{"tool", "input", "state", "database", "supporting-file", "rules"} {
		t.Run(kind, func(t *testing.T) {
			spec, limits, _ := frozenFixture(t)
			path := map[string]string{"tool": spec.ToolPath, "input": spec.InputPath, "state": filepath.Join(spec.StatePath, "bin", "entrypoint"), "database": filepath.Join(spec.DatabasePath, "db", "data.bin"), "supporting-file": filepath.Join(spec.DatabasePath, "support.txt"), "rules": filepath.Join(spec.RulePackPath, "rules.yml")}[kind]
			if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits); err == nil || cleanup != nil {
				t.Fatalf("unapproved %s was frozen: %v", kind, err)
			}
			matches, err := filepath.Glob(filepath.Join(filepath.Dir(spec.TemporaryDir), ".pao-frozen-*"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("failed freeze leaked private copies: %v %v", matches, err)
			}
		})
	}
}

func TestFreezeInputsRefusesUnknownFilesAndUnapprovedManifest(t *testing.T) {
	for _, kind := range []string{"state-extra", "database-extra", "rules-extra", "state-identity", "manifest-digest", "missing-input-digest", "missing-tool-digest"} {
		t.Run(kind, func(t *testing.T) {
			spec, limits, _ := frozenFixture(t)
			switch kind {
			case "state-extra":
				frozenWriteTestFile(t, filepath.Join(spec.StatePath, "extra.txt"), []byte("extra"), 0o600)
			case "database-extra":
				frozenWriteTestFile(t, filepath.Join(spec.DatabasePath, "extra.txt"), []byte("extra"), 0o600)
			case "rules-extra":
				frozenWriteTestFile(t, filepath.Join(spec.RulePackPath, "extra.txt"), []byte("extra"), 0o600)
			case "state-identity":
				spec.StateDigest = frozenWriteTestJSON(t, filepath.Join(spec.StatePath, preparedStateManifestName), preparedStateManifest{APIVersion: "pao.dev/prepared-state/v1alpha1", AdapterID: "another", Files: []preparedStateFile{{"bin/entrypoint", strings.TrimPrefix(frozenTestDigest([]byte("approved-state")), "sha256:")}}})
			case "manifest-digest":
				spec.StateDigest = frozenTestDigest([]byte("unapproved manifest"))
			case "missing-input-digest":
				spec.InputDigest = ""
			case "missing-tool-digest":
				spec.ToolDigest = ""
			}
			if _, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits); err == nil || cleanup != nil {
				t.Fatalf("invalid capsule was frozen: %v", err)
			}
		})
	}
}

func TestFreezeInputsResourceQuotasStopBeforeLaunch(t *testing.T) {
	for _, kind := range []string{"per-file", "total", "entries", "manifest", "tree-file"} {
		t.Run(kind, func(t *testing.T) {
			spec, limits, _ := frozenFixture(t)
			switch kind {
			case "per-file":
				limits.MaxFileBytes = 8
			case "total":
				limits.MaxTotalBytes = 20
			case "entries":
				limits.MaxEntries = 4
			case "manifest":
				limits.MaxManifestBytes = 8
			case "tree-file":
				limits.MaxFileBytes = 12
				spec.ToolDigest = frozenWriteTestFile(t, spec.ToolPath, []byte("small"), 0o755)
				spec.InputPath, spec.InputDigest = "", ""
			}
			if _, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits); err == nil || cleanup != nil {
				t.Fatalf("resource limit %s did not refuse: %v", kind, err)
			}
		})
	}
}

func TestFrozenCopyChecksCancellationAndExactActualCounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limits := FrozenInputLimits{frozenCopyBufferBytes + 8, frozenCopyBufferBytes + 8, 4, 8}
	session := frozenSession{limits: limits}
	source := &frozenMeasuredReader{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, frozenCopyBufferBytes+8))}
	destination := &frozenReactingWriter{afterWrite: func() { cancel() }}
	err := session.copyExactly(ctx, destination, source, frozenCopyBufferBytes+8, true)
	if !errors.Is(err, context.Canceled) || source.bytes != frozenCopyBufferBytes || session.read != frozenCopyBufferBytes || session.written != frozenCopyBufferBytes || destination.Len() != frozenCopyBufferBytes || source.calls != 1 {
		t.Fatalf("cancellation/count mismatch: read=%d written=%d calls=%d err=%v", session.read, session.written, source.calls, err)
	}
}

type frozenMeasuredReader struct {
	reader io.Reader
	bytes  int
	calls  int
}

func (r *frozenMeasuredReader) Read(content []byte) (int, error) {
	n, err := r.reader.Read(content)
	r.bytes += n
	r.calls++
	return n, err
}

type frozenReactingWriter struct {
	bytes.Buffer
	afterWrite func()
}

func (w *frozenReactingWriter) Write(content []byte) (int, error) {
	n, err := w.Buffer.Write(content)
	if w.afterWrite != nil {
		callback := w.afterWrite
		w.afterWrite = nil
		callback()
	}
	return n, err
}

func TestFrozenCopyStopsAtInitialSizeWhenSourceGrows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	frozenWriteTestFile(t, path, []byte("small"), 0o600)
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	initial, _ := source.Stat()
	session := frozenSession{limits: FrozenInputLimits{8, 8, 4, 8}}
	destination := &frozenReactingWriter{afterWrite: func() {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.WriteString("growth")
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
	}}
	if err := session.copyExactly(context.Background(), destination, source, initial.Size(), true); err != nil {
		t.Fatal(err)
	}
	changed, _ := source.Stat()
	if frozenUnchanged(initial, changed) || session.written != 5 || session.read != 5 || destination.Len() != 5 {
		t.Fatalf("growing source exceeded copy bound or drift went unnoticed: %#v", session)
	}
}

func TestFreezeInputsCanceledBeforeCreationAndCleanupIsOwned(t *testing.T) {
	spec, limits, _ := frozenFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, cleanup, err := FreezeInputsWithLimits(ctx, spec, limits); !errors.Is(err, context.Canceled) || cleanup != nil {
		t.Fatalf("canceled freeze was accepted: %v", err)
	}
	frozen, cleanup, err := FreezeInputsWithLimits(context.Background(), spec, limits)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(filepath.Dir(frozen.ToolPath))
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("owned copy was not removed: %v", err)
	}
	if _, err := os.Stat(spec.ToolPath); err != nil {
		t.Fatalf("cleanup touched original input: %v", err)
	}
	if _, err := os.Stat(spec.TemporaryDir); err != nil {
		t.Fatalf("cleanup touched output: %v", err)
	}
}

func TestFreezeExecutableHelper(t *testing.T) {
	if os.Getenv("PAO_FROZEN_HELPER") != "1" {
		return
	}
	fmt.Print("APPROVED-FROZEN-EXECUTABLE")
	os.Exit(0)
}

func TestFrozenExecutableRunsApprovedBytesAfterOriginalReplacement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	name := "inert-helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(parent, "source", name)
	digest := frozenWriteTestFile(t, path, body, 0o755)
	frozen, cleanup, err := FreezeExecutableIn(context.Background(), path, digest, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Rename(filepath.Dir(path), filepath.Join(parent, "previous-source")); err != nil {
		t.Fatal(err)
	}
	frozenWriteTestFile(t, path, []byte("replacement is not executable"), 0o755)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, frozen, "-test.run=^TestFreezeExecutableHelper$")
	command.Env = []string{"PAO_FROZEN_HELPER=1"}
	if runtime.GOOS == "windows" {
		command.Env = append(command.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "APPROVED-FROZEN-EXECUTABLE" {
		t.Fatalf("frozen native execution did not use approved bytes: %q %v", output, err)
	}
}
