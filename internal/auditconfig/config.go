// Package auditconfig reads data-only operator configuration outside audit targets.
package auditconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
)

const Version = "pao.dev/local-audit-config/v1"
const PortableVersion = "pao.dev/local-audit-config/v2"
const MaxBytes = 64 << 10

type Config struct {
	Version                string `json:"version"`
	Target                 string `json:"target"`
	EvidenceBase           string `json:"evidence_base"`
	ReportBase             string `json:"report_base"`
	ToolchainRoot          string `json:"toolchain_root"`
	RulePackRoot           string `json:"rule_pack_root"`
	ManifestRoot           string `json:"manifest_root"`
	DockerBaseProvider     string `json:"docker_base_provider"`
	DockerScanCodeProvider string `json:"docker_scancode_provider"`
	ToolchainCatalog       string `json:"toolchain_catalog,omitempty"`
}

// Decode rejects duplicate and case-variant keys (encoding/json alone accepts both),
// nulls, non-string values, trailing JSON, and unknown fields, including safety overrides.
func Decode(data []byte) (Config, error) {
	var c Config
	if len(data) > MaxBytes || !utf8.Valid(data) {
		return c, errors.New("configuration exceeds the UTF-8/size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return c, errors.New("configuration must be one JSON object")
	}
	allowed := map[string]bool{"version": true, "target": true, "evidence_base": true, "report_base": true, "toolchain_root": true, "rule_pack_root": true, "manifest_root": true, "docker_base_provider": true, "docker_scancode_provider": true, "toolchain_catalog": true}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return c, errors.New("invalid JSON field")
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return c, errors.New("unknown or duplicate configuration field")
		}
		seen[key] = true
		value, err := d.Token()
		text, ok := value.(string)
		if err != nil || !ok || strings.ContainsAny(text, "\x00\r\n") {
			return c, errors.New("configuration fields must be strings without control line breaks")
		}
	}
	if _, err := d.Token(); err != nil {
		return c, errors.New("invalid JSON object")
	}
	if _, err := d.Token(); err != io.EOF {
		return c, errors.New("trailing configuration content")
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if c.Version != Version && c.Version != PortableVersion {
		return c, errors.New("unsupported configuration version")
	}
	required := []string{c.Target, c.EvidenceBase, c.ReportBase, c.ToolchainRoot, c.ManifestRoot}
	if c.Version == Version {
		if seen["toolchain_catalog"] {
			return c, errors.New("toolchain_catalog requires configuration v2")
		}
		required = append(required, c.RulePackRoot, c.DockerBaseProvider, c.DockerScanCodeProvider)
	} else {
		required = append(required, c.ToolchainCatalog)
	}
	for _, value := range required {
		if value == "" {
			return c, errors.New("required configuration field is empty or missing")
		}
	}
	return c, nil
}

func Resolve(name string) (string, error) {
	if name == "" {
		return "", errors.New("--config is required")
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	if filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return "", errors.New("config must be an absolute file or a name in the private config directory")
	}
	base, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(base) {
		return "", errors.New("use an absolute private --config path on this host")
	}
	return filepath.Join(base, "PAO", "config", name), nil
}

func Load(path string) (Config, error) {
	var c Config
	if err := CheckPath(path, false); err != nil {
		return c, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return c, errors.New("configuration must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return c, err
	}
	c, err = Decode(data)
	if err != nil {
		return c, err
	}
	return c, c.ValidatePaths(path)
}

func (c Config) Digest() string {
	data, _ := json.Marshal(c)
	return Digest(data)
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c Config) ValidatePaths(configPath string) error {
	paths := []struct {
		name, path string
		mustExist  bool
	}{
		{"target", c.Target, true}, {"evidence", c.EvidenceBase, false}, {"report", c.ReportBase, false},
		{"toolchain", c.ToolchainRoot, true}, {"rule pack", c.RulePackRoot, true}, {"manifests", c.ManifestRoot, true},
		{"base Docker provider", c.DockerBaseProvider, true}, {"ScanCode Docker provider", c.DockerScanCodeProvider, true},
		{"toolchain catalog", c.ToolchainCatalog, true},
	}
	for _, entry := range paths {
		if entry.path == "" && (c.Version == PortableVersion || entry.name == "toolchain catalog") {
			continue
		}
		if err := CheckPath(entry.path, !entry.mustExist); err != nil {
			return fmt.Errorf("%s: %w", entry.name, err)
		}
		info, err := os.Stat(entry.path)
		isFile := entry.name == "base Docker provider" || entry.name == "ScanCode Docker provider" || entry.name == "toolchain catalog"
		if err == nil && isFile && !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", entry.name)
		}
		if err == nil && !isFile && !info.IsDir() {
			return fmt.Errorf("%s must be a directory", entry.name)
		}
		if err != nil && (!os.IsNotExist(err) || entry.mustExist) {
			return fmt.Errorf("%s directory is unavailable", entry.name)
		}
	}
	// Reject overlap in either direction: auditing a parent of private state would expose it.
	for _, path := range []string{filepath.Dir(configPath), c.EvidenceBase, c.ReportBase, c.ToolchainRoot, c.RulePackRoot, c.ManifestRoot, c.DockerBaseProvider, c.DockerScanCodeProvider, c.ToolchainCatalog} {
		if Overlap(c.Target, path) {
			return errors.New("target must be separate from configuration, outputs and trusted inputs")
		}
	}
	if Overlap(c.EvidenceBase, c.ReportBase) {
		return errors.New("raw evidence and portable reports must be separate")
	}
	for _, output := range []string{c.EvidenceBase, c.ReportBase} {
		for _, input := range []string{filepath.Dir(configPath), c.ToolchainRoot, c.RulePackRoot, c.ManifestRoot, c.DockerBaseProvider, c.DockerScanCodeProvider, c.ToolchainCatalog} {
			if Overlap(output, input) {
				return errors.New("output directories must be separate from configuration and trusted inputs")
			}
		}
	}
	return nil
}

func Overlap(a, b string) bool {
	return a != "" && b != "" && (target.IsInside(a, b) || target.IsInside(b, a))
}

// CheckPath checks every existing ancestor, including Windows junctions, and refuses
// network/device paths. Missing output descendants are allowed, never broken links.
func CheckPath(path string, allowMissing bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || strings.ContainsRune(path, '\x00') {
		return errors.New("a clean absolute local path is required")
	}
	if !localPath(path) {
		return errors.New("fixed-drive paths without device aliases are required")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			if !os.IsNotExist(err) || !allowMissing {
				return errors.New("path or ancestor is unavailable")
			}
		} else {
			if info.Mode()&os.ModeSymlink != 0 || reparse(current) {
				return errors.New("linked or redirected paths are forbidden")
			}
			if current != path && !info.IsDir() {
				return errors.New("path ancestor is not a directory")
			}
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
