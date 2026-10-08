package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
)

const (
	// Current owner-approved Grype databases can exceed 2 GiB. The aggregate
	// payload and actual-read budgets remain independent hard ceilings.
	FrozenMaxFileBytes     int64 = 4 << 30
	FrozenMaxTotalBytes    int64 = 8 << 30
	FrozenMaxEntries             = 100000
	FrozenMaxManifestBytes int64 = 16 << 20
)

// FrozenInputLimits apply to the complete per-run payload. Source and readback
// I/O share an additional hard ceiling of three times MaxTotalBytes; manifests
// are read a third time for bounded parsing. Values may only lower hard caps.
type FrozenInputLimits struct {
	MaxFileBytes     int64
	MaxTotalBytes    int64
	MaxEntries       int
	MaxManifestBytes int64
}

func DefaultFrozenInputLimits() FrozenInputLimits {
	return FrozenInputLimits{FrozenMaxFileBytes, FrozenMaxTotalBytes, FrozenMaxEntries, FrozenMaxManifestBytes}
}

func (l FrozenInputLimits) validate() error {
	if l.MaxFileBytes <= 0 || l.MaxFileBytes > FrozenMaxFileBytes || l.MaxTotalBytes <= 0 || l.MaxTotalBytes > FrozenMaxTotalBytes || l.MaxEntries <= 0 || l.MaxEntries > FrozenMaxEntries || l.MaxManifestBytes <= 0 || l.MaxManifestBytes > FrozenMaxManifestBytes {
		return errors.New("frozen input limits must be positive and within hard caps")
	}
	return nil
}

type frozenSession struct {
	root       string
	parent     string
	identity   os.FileInfo
	limits     FrozenInputLimits
	written    int64
	read       int64
	entries    int
	examined   int
	handles    []*os.File
	ownedPaths []string
	// Test-only barrier; exported production APIs never accept injected hooks.
	afterCopy func(string, string) error
}

func newFrozenSession(parent string, limits FrozenInputLimits) (*frozenSession, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := auditconfig.CheckPath(parent, false); err != nil {
		return nil, fmt.Errorf("private frozen-input parent: %w", err)
	}
	if err := frozenCheckPrivateParent(parent); err != nil {
		return nil, err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return nil, errors.New("private frozen-input parent must be a directory")
	}
	var root string
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		root = filepath.Join(parent, ".pao-frozen-"+hex.EncodeToString(nonce[:]))
		if err := auditconfig.MakePrivateDirectory(root); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, err
		}
		identity, err := frozenIdentity(root)
		if err != nil {
			// No file contents have been written. Preserve the directory if its
			// identity could not be established rather than deleting a new path.
			return nil, err
		}
		session := &frozenSession{root: root, parent: parent, identity: identity, limits: limits}
		baseHandle, err := frozenHoldPrivate(root, true)
		if err != nil {
			cleanup := session.cleanupFunc()
			return nil, errors.Join(err, cleanup())
		}
		if baseHandle != nil {
			session.handles = append(session.handles, baseHandle)
		}
		return session, nil
	}
	return nil, errors.New("cannot reserve a private frozen-input directory")
}

func (s *frozenSession) cleanupFunc() func() error {
	var once sync.Once
	var cleanupErr error
	return func() error {
		once.Do(func() {
			for index := len(s.handles) - 1; index >= 0; index-- {
				cleanupErr = errors.Join(cleanupErr, s.handles[index].Close())
			}
			if filepath.Dir(s.root) != s.parent || !strings.HasPrefix(filepath.Base(s.root), ".pao-frozen-") {
				cleanupErr = errors.Join(cleanupErr, errors.New("refuse cleanup outside owned frozen-input directory"))
				return
			}
			current, err := os.Lstat(s.root)
			if os.IsNotExist(err) {
				return
			}
			if err != nil || !os.SameFile(s.identity, current) || !current.IsDir() || auditconfig.CheckPath(s.root, false) != nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("refuse cleanup of changed frozen-input directory"))
				return
			}
			// Restore only modes on our bounded, recorded paths. This is needed
			// for Unix removal and Windows readonly-attribute removal.
			for _, path := range s.ownedPaths {
				if err := auditconfig.CheckPath(path, false); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
					return
				}
				if err := os.Chmod(path, 0o700); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
					return
				}
			}
			cleanupErr = errors.Join(cleanupErr, os.RemoveAll(s.root))
		})
		return cleanupErr
	}
}

func FreezeInputs(ctx context.Context, spec ExecutionSpec) (ExecutionSpec, func() error, error) {
	return FreezeInputsWithLimits(ctx, spec, DefaultFrozenInputLimits())
}

func FreezeInputsWithLimits(ctx context.Context, spec ExecutionSpec, limits FrozenInputLimits) (ExecutionSpec, func() error, error) {
	return freezeInputs(ctx, spec, limits, nil)
}

func freezeInputs(ctx context.Context, spec ExecutionSpec, limits FrozenInputLimits, afterCopy func(string, string) error) (ExecutionSpec, func() error, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionSpec{}, nil, err
	}
	if err := spec.Validate(); err != nil {
		return ExecutionSpec{}, nil, err
	}
	if !sha256Reference.MatchString(spec.ToolDigest) || (spec.InputPath != "" && !sha256Reference.MatchString(spec.InputDigest)) {
		return ExecutionSpec{}, nil, errors.New("freezing requires approved tool and captured-input SHA-256 digests")
	}
	sources := []string{spec.ToolPath, spec.InputPath, spec.StatePath, spec.DatabasePath, spec.RulePackPath}
	for _, source := range sources {
		if source == "" {
			continue
		}
		if auditconfig.Overlap(source, spec.TargetRoot) || auditconfig.Overlap(source, spec.TemporaryDir) {
			return ExecutionSpec{}, nil, errors.New("frozen prerequisites must be separate from target and output")
		}
		if err := auditconfig.CheckPath(source, false); err != nil {
			return ExecutionSpec{}, nil, err
		}
	}
	session, err := newFrozenSession(filepath.Dir(spec.TemporaryDir), limits)
	if err != nil {
		return ExecutionSpec{}, nil, err
	}
	cleanup := session.cleanupFunc()
	fail := func(err error) (ExecutionSpec, func() error, error) {
		return ExecutionSpec{}, nil, errors.Join(err, cleanup())
	}
	for _, source := range append(sources, spec.TargetRoot, spec.TemporaryDir) {
		if auditconfig.Overlap(source, session.root) {
			return fail(errors.New("private frozen-input directory overlaps an input or output"))
		}
	}
	session.afterCopy = afterCopy
	frozen := spec
	mapping := map[string]string{}
	fileInputs := []struct {
		kind, source, digest string
		destination          *string
	}{{"tool", spec.ToolPath, spec.ToolDigest, &frozen.ToolPath}, {"input", spec.InputPath, spec.InputDigest, &frozen.InputPath}}
	for _, input := range fileInputs {
		if input.source == "" {
			continue
		}
		directory := filepath.Join(session.root, input.kind)
		if err := session.makeDirectory(directory); err != nil {
			return fail(err)
		}
		destination := filepath.Join(directory, filepath.Base(input.source))
		observed, err := session.copyFile(ctx, nil, input.source, destination)
		if err != nil || observed.digest != input.digest {
			return fail(errors.Join(err, fmt.Errorf("%s frozen digest does not match approval", input.kind)))
		}
		*input.destination = destination
		mapping[input.source] = destination
	}
	trees := []struct {
		kind, source, digest string
		destination          *string
	}{{"state", spec.StatePath, spec.StateDigest, &frozen.StatePath}, {"database", spec.DatabasePath, spec.DatabaseDigest, &frozen.DatabasePath}, {"rules", spec.RulePackPath, spec.RulePackDigest, &frozen.RulePackPath}}
	for _, input := range trees {
		if input.source == "" {
			continue
		}
		destination := filepath.Join(session.root, input.kind)
		observed, err := session.copyTree(ctx, input.source, destination)
		if err != nil {
			return fail(err)
		}
		if err := session.verifyCapsule(ctx, destination, input.kind, input.digest, spec.AdapterID, observed); err != nil {
			return fail(err)
		}
		*input.destination = destination
		mapping[input.source] = destination
	}
	frozen.Arguments = remapFrozenArguments(spec.Arguments, mapping)
	if err := frozen.Validate(); err != nil {
		return fail(err)
	}
	if err := session.seal(ctx); err != nil {
		return fail(err)
	}
	return frozen, cleanup, nil
}

func remapFrozenArguments(arguments []string, mapping map[string]string) []string {
	paths := make([]string, 0, len(mapping))
	for path := range mapping {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	remapped := append([]string(nil), arguments...)
	for index, argument := range remapped {
		for _, path := range paths {
			argument = strings.ReplaceAll(argument, path, mapping[path])
		}
		remapped[index] = argument
	}
	return remapped
}

// FreezeExecutableIn copies one explicitly hashed native executable into a
// caller-selected private parent. DLLs/plugins are not implicitly copied or
// approved; native CLI compatibility needs separate acceptance evidence.
func FreezeExecutableIn(ctx context.Context, path, digest, privateParent string) (string, func() error, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if !sha256Reference.MatchString(digest) || auditconfig.CheckPath(path, false) != nil {
		return "", nil, errors.New("native executable requires a safe path and approved SHA-256")
	}
	session, err := newFrozenSession(privateParent, DefaultFrozenInputLimits())
	if err != nil {
		return "", nil, err
	}
	cleanup := session.cleanupFunc()
	if auditconfig.Overlap(path, session.root) {
		return "", nil, errors.Join(errors.New("native frozen executable overlaps source"), cleanup())
	}
	directory := filepath.Join(session.root, "native")
	if err := session.makeDirectory(directory); err != nil {
		return "", nil, errors.Join(err, cleanup())
	}
	destination := filepath.Join(directory, filepath.Base(path))
	observed, err := session.copyFile(ctx, nil, path, destination)
	if err != nil || observed.digest != digest {
		return "", nil, errors.Join(err, errors.New("native frozen executable digest mismatch"), cleanup())
	}
	if err := session.seal(ctx); err != nil {
		return "", nil, errors.Join(err, cleanup())
	}
	return destination, cleanup, nil
}
