package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

type PreparedCLI struct {
	Version    string `json:"version"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SourcePath string `json:"source_path"`
	Platform   string `json:"platform"`
}

// PrepareDockerCLI runs only in setup. Linux receives a new immutable private
// generation; Windows retains the installed layout and deny-write pinning.
func PrepareDockerCLI(ctx context.Context, sourcePath, expectedDigest, installationState string) (PreparedCLI, error) {
	var result PreparedCLI
	if !sha256Reference.MatchString(expectedDigest) {
		return result, errors.New("Docker CLI requires an exact SHA-256")
	}
	canonical, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		return result, err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return result, err
	}
	if err = verifyDockerCLI(canonical, expectedDigest); err != nil {
		return result, err
	}
	s, err := installation.Open(installationState)
	if err != nil {
		return result, err
	}
	lease, err := s.Lock(ctx, true)
	if err != nil {
		return result, err
	}
	defer lease.Close()
	pending, err := s.Pending()
	if err != nil {
		return result, err
	}
	if len(pending) != 0 {
		return result, errors.New("RECOVERY_REQUIRED: resolve pending containers before setup")
	}
	dir := preparedCLIDirectory(installationState, expectedDigest)
	if _, err := os.Lstat(dir); err == nil {
		result, err = readPreparedCLI(installationState, expectedDigest)
		if err != nil {
			return result, err
		}
		if result.SourcePath != canonical {
			return result, errors.New("existing CLI generation has a different canonical source")
		}
		return result, nil
	} else if !os.IsNotExist(err) {
		return result, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return result, err
	}
	temporary := filepath.Join(installationState, "native", ".prepare-"+hex.EncodeToString(nonce[:]))
	if err := auditconfig.MakePrivateDirectory(temporary); err != nil {
		return result, err
	}
	result = PreparedCLI{Version: "pao.dev/prepared-cli/v1", Path: canonical, SHA256: expectedDigest, SourcePath: canonical, Platform: runtime.GOOS}
	if runtime.GOOS == "windows" {
		release, err := PinExecutable(ctx, canonical, expectedDigest)
		if err != nil {
			return result, err
		}
		defer release()
	} else if runtime.GOOS == "linux" {
		frozen, release, err := FreezeExecutableIn(ctx, canonical, expectedDigest, installationState)
		if err != nil {
			return result, err
		}
		defer release()
		in, err := os.Open(frozen)
		if err != nil {
			return result, err
		}
		defer in.Close()
		result.Path = filepath.Join(dir, "docker")
		copiedPath := filepath.Join(temporary, "docker")
		out, err := os.OpenFile(copiedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0500)
		if err != nil {
			return result, err
		}
		_, copyErr := io.Copy(out, io.LimitReader(in, FrozenMaxFileBytes+1))
		err = errors.Join(copyErr, out.Sync(), out.Close())
		if err != nil {
			return result, err
		}
		if err = verifyDockerCLI(copiedPath, expectedDigest); err != nil {
			return result, err
		}
	} else {
		return result, errors.New("Docker CLI preparation supports Windows and Linux only")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	f, err := os.OpenFile(filepath.Join(temporary, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	_, err = f.Write(raw)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return result, err
	}
	if err := os.Rename(temporary, dir); err != nil {
		return result, err
	}
	if runtime.GOOS == "linux" {
		directory, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return result, err
		}
		err = errors.Join(directory.Sync(), directory.Close())
		if err != nil {
			return result, err
		}
	}
	return readPreparedCLI(installationState, expectedDigest)
}

func preparedCLIDirectory(root, digest string) string {
	return filepath.Join(root, "native", strings.TrimPrefix(digest, "sha256:")+"-"+runtime.GOOS)
}

func readPreparedCLI(root, digest string) (PreparedCLI, error) {
	var p PreparedCLI
	if !sha256Reference.MatchString(digest) {
		return p, errors.New("invalid Docker CLI digest")
	}
	dir := preparedCLIDirectory(root, digest)
	if err := installation.ValidatePrivatePath(dir, true); err != nil {
		return p, errors.New("SETUP_REQUIRED: private Docker CLI generation is unavailable")
	}
	path := filepath.Join(dir, "manifest.json")
	if err := installation.ValidatePrivatePath(path, false); err != nil {
		return p, err
	}
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil {
		return p, err
	}
	if err = strictjson.Decode(raw, &p, 64<<10); err != nil {
		return p, err
	}
	if p.Version != "pao.dev/prepared-cli/v1" || p.SHA256 != digest || p.Platform != runtime.GOOS || !filepath.IsAbs(p.SourcePath) {
		return p, errors.New("invalid prepared Docker CLI manifest")
	}
	want := p.SourcePath
	if runtime.GOOS == "linux" {
		want = filepath.Join(dir, "docker")
	}
	if p.Path != want {
		return p, errors.New("prepared Docker CLI path differs from its generation")
	}
	if runtime.GOOS == "linux" {
		if err := installation.ValidatePrivatePath(p.Path, false); err != nil {
			return p, err
		}
	}
	if err := verifyDockerCLI(p.Path, p.SHA256); err != nil {
		return p, err
	}
	return p, nil
}

// prepareReadOnlyControl assumes a held installation lease. It creates no files.
func prepareReadOnlyControl(ctx context.Context, h DockerHost, state string) (DockerHost, func() error, error) {
	p, err := readPreparedCLI(state, h.DockerSHA256)
	if err != nil {
		return h, nil, err
	}
	if h.DockerPath != p.Path {
		return h, nil, errors.New("SETUP_REQUIRED: provider CLI differs from prepared generation")
	}
	if runtime.GOOS == "windows" {
		release, err := PinExecutable(ctx, p.Path, p.SHA256)
		if err != nil {
			return h, nil, err
		}
		h.preparedNative = true
		return h, release, nil
	}
	f, closeAll, err := frozenOpenChain(p.Path, false)
	if err != nil {
		return h, nil, err
	}
	if _, err = f.Stat(); err != nil {
		closeAll()
		return h, nil, err
	}
	h.preparedNative = true
	return h, func() error { closeAll(); return nil }, nil
}

// CheckPreparedRuntime is a read-only readiness probe, not an isolation test or
// a security verdict. A missing prepared generation yields SETUP_REQUIRED.
func CheckPreparedRuntime(ctx context.Context, provider DockerProviderConfig, state string) (SandboxProperties, error) {
	if err := provider.Validate(time.Now().UTC()); err != nil {
		return SandboxProperties{}, err
	}
	s, err := installation.Open(state)
	if err != nil {
		return SandboxProperties{}, err
	}
	l, err := s.Lock(ctx, false)
	if err != nil {
		return SandboxProperties{}, err
	}
	defer l.Close()
	pending, err := s.Pending()
	if err != nil {
		return SandboxProperties{}, err
	}
	if len(pending) != 0 {
		return SandboxProperties{}, errors.New("RECOVERY_REQUIRED: installation contains pending containers")
	}
	h, release, err := prepareReadOnlyControl(ctx, provider.Host(), state)
	if err != nil {
		return SandboxProperties{}, err
	}
	defer release()
	return h.Capabilities(ctx)
}
