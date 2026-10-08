package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

const DockerProviderConfigVersion = "pao.dev/docker-provider/v1alpha1"
const maxDockerConfigBytes int64 = 1 << 20

// DockerProviderConfig is a separately reviewed, static local host configuration.
// It contains no registry credential, image URL or mutable tag.
type DockerProviderConfig struct {
	APIVersion      string          `json:"api_version"`
	DockerPath      string          `json:"docker_path"`
	DockerSHA256    string          `json:"docker_sha256"`
	RuntimeImage    string          `json:"runtime_image"`
	RuntimeApproval RuntimeApproval `json:"runtime_approval"`
}

func (c DockerProviderConfig) Validate(now time.Time) error {
	if c.APIVersion != DockerProviderConfigVersion {
		return fmt.Errorf("Docker provider config requires api_version %q", DockerProviderConfigVersion)
	}
	if !filepath.IsAbs(c.DockerPath) {
		return errors.New("Docker provider config requires an absolute Docker CLI path")
	}
	if !sha256Reference.MatchString(c.DockerSHA256) {
		return errors.New("Docker provider config requires an exact Docker CLI SHA-256")
	}
	if err := validateImageID(c.RuntimeImage); err != nil {
		return err
	}
	return c.RuntimeApproval.Validate(now)
}

func (c DockerProviderConfig) Host() DockerHost {
	return DockerHost{DockerPath: c.DockerPath, DockerSHA256: c.DockerSHA256, RuntimeImage: c.RuntimeImage, RuntimeApproval: c.RuntimeApproval}
}

func LoadDockerProviderConfig(path string, now time.Time) (DockerProviderConfig, error) {
	if !filepath.IsAbs(path) {
		return DockerProviderConfig{}, errors.New("Docker provider config path must be absolute")
	}
	if err := auditconfig.CheckPath(path, false); err != nil {
		return DockerProviderConfig{}, errors.New("Docker provider config path is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxDockerConfigBytes {
		return DockerProviderConfig{}, errors.New("Docker provider config must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return DockerProviderConfig{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxDockerConfigBytes+1))
	if err != nil {
		return DockerProviderConfig{}, err
	}
	var config DockerProviderConfig
	if err := strictjson.Decode(raw, &config, int(maxDockerConfigBytes)); err != nil {
		return DockerProviderConfig{}, fmt.Errorf("decode Docker provider config: %w", err)
	}
	if err := config.Validate(now); err != nil {
		return DockerProviderConfig{}, err
	}
	if err := verifyDockerCLI(config.DockerPath, config.DockerSHA256); err != nil {
		return DockerProviderConfig{}, err
	}
	return config, nil
}

func verifyDockerCLI(path, expected string) error {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return errors.New("Docker CLI path is unsafe")
	}
	if err := verifyRegularFileDigest(path, expected); err != nil {
		return errors.New("Docker CLI digest does not match provider approval")
	}
	return nil
}

func verifyRegularFileDigest(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > FrozenMaxFileBytes {
		return errors.New("path must be a regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return errors.New("executable changed before bounded verification")
	}
	h := sha256.New()
	bytes, err := io.Copy(h, io.LimitReader(f, FrozenMaxFileBytes+1))
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil || bytes != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return errors.New("executable grew or changed during bounded verification")
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("digest mismatch")
	}
	return nil
}
