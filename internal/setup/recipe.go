// Package setup prepares explicitly approved scanner dependencies separately
// from an audit. No preparation operation accepts target contents.
package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

const RecipeVersion = "pao.dev/setup-recipes/v1"
const PlanVersion = "pao.dev/setup-plan/v1"
const maxRecipeBytes = 2 << 20

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var recipeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// Artifact is an immutable public input, not a command or an executable plugin.
type Artifact struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Filename string `json:"filename"`
	License  string `json:"license"`
	Purpose  string `json:"purpose"`
}

type ToolRecipe struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	Artifact     string `json:"artifact"`
	Format       string `json:"format"`
	Member       string `json:"member,omitempty"`
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	License      string `json:"license"`
	LicenseURL   string `json:"license_url"`
}

type Recipes struct {
	APIVersion        string            `json:"api_version"`
	RuntimeImage      string            `json:"runtime_image"`
	RuntimeSource     string            `json:"runtime_source"`
	RuntimeLicenseURL string            `json:"runtime_license_url"`
	Artifacts         []Artifact        `json:"artifacts"`
	Tools             []ToolRecipe      `json:"tools"`
	Payload           map[string]string `json:"payload"`
	Digest            string            `json:"-"`
}

type Plan struct {
	APIVersion       string       `json:"api_version"`
	Profile          string       `json:"profile"`
	Root             string       `json:"root"`
	RecipeDigest     string       `json:"recipe_digest"`
	RuntimeImage     string       `json:"runtime_image"`
	Artifacts        []Artifact   `json:"artifacts"`
	Tools            []ToolRecipe `json:"tools"`
	DownloadBytes    int64        `json:"pinned_download_bytes"`
	DynamicDatabases []string     `json:"dynamic_databases"`
	MinimumFreeBytes int64        `json:"minimum_free_bytes"`
	Network          string       `json:"network"`
	TargetAccess     string       `json:"target_access"`
	Digest           string       `json:"plan_digest"`
}

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func publicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return errors.New("recipe URL must be credential-free HTTPS")
	}
	switch u.Hostname() {
	case "github.com", "files.pythonhosted.org", "deb.debian.org", "snapshot.debian.org", "raw.githubusercontent.com", "www.python.org", "hub.docker.com", "pypi.org", "grype.anchore.io", "storage.googleapis.com", "ghcr.io":
		return nil
	}
	return errors.New("recipe URL host is not admitted")
}

func decodeRecipes(raw []byte) (Recipes, error) {
	var r Recipes
	if err := strictjson.Decode(raw, &r, maxRecipeBytes); err != nil {
		return r, err
	}
	if r.APIVersion != RecipeVersion || len(r.Tools) != 10 || len(r.Artifacts) < 10 || len(r.Artifacts) > 100 || !regexp.MustCompile(`^docker.io/library/python@sha256:[a-f0-9]{64}$`).MatchString(r.RuntimeImage) {
		return r, errors.New("invalid setup recipe identity or inventory")
	}
	artifacts := map[string]Artifact{}
	for _, a := range r.Artifacts {
		if !recipeIDPattern.MatchString(a.ID) || !digestPattern.MatchString(a.SHA256) || a.Bytes <= 0 || a.Bytes > 512<<20 || filepath.Base(a.Filename) != a.Filename || strings.ContainsAny(a.Filename, `\\/:`) || a.License == "" || a.Purpose == "" {
			return r, fmt.Errorf("invalid recipe artifact: %s", a.ID)
		}
		if err := publicURL(a.URL); err != nil {
			return r, err
		}
		if _, ok := artifacts[a.ID]; ok {
			return r, errors.New("duplicate recipe artifact")
		}
		artifacts[a.ID] = a
	}
	seen := map[string]bool{}
	for _, t := range r.Tools {
		switch t.ID {
		case "gitleaks", "grype", "syft", "sbomqs", "osv-scanner", "trivy", "zizmor", "scancode", "reuse", "opengrep":
		default:
			return r, errors.New("unowned setup tool")
		}
		if seen[t.ID] || artifacts[t.Artifact].ID == "" || t.Version == "" || t.License == "" {
			return r, errors.New("invalid tool recipe")
		}
		seen[t.ID] = true
		if err := publicURL(t.LicenseURL); err != nil {
			return r, err
		}
		switch t.Format {
		case "raw", "tar.gz", "scancode", "reuse":
		default:
			return r, errors.New("unsupported immutable artifact format")
		}
		if t.BinarySHA256 != "" && !digestPattern.MatchString(t.BinarySHA256) {
			return r, errors.New("invalid tool binary digest")
		}
		if t.Member != "" && !safeRelative(t.Member) {
			return r, errors.New("unsafe tool archive member")
		}
	}
	if len(r.Payload) == 0 {
		return r, errors.New("recipe payload hashes required")
	}
	for p, h := range r.Payload {
		if !safeRelative(p) || !digestPattern.MatchString(h) {
			return r, errors.New("invalid recipe payload")
		}
	}
	r.Digest = hashBytes(raw)
	return r, nil
}

// LoadRecipes checks the recipe against the extracted package's content manifest.
// It never consults a network service or a source checkout.
func LoadRecipes(packageRoot string) (Recipes, error) {
	var zero Recipes
	if err := auditconfig.CheckPath(packageRoot, false); err != nil {
		return zero, err
	}
	manifest, err := readBounded(filepath.Join(packageRoot, "PACKAGE-CONTENTS.json"), maxRecipeBytes)
	if err != nil {
		return zero, fmt.Errorf("verified extracted package required: %w", err)
	}
	var content map[string]string
	if err := strictjson.Decode(manifest, &content, maxRecipeBytes); err != nil {
		return zero, err
	}
	raw, err := readBounded(filepath.Join(packageRoot, "recipes", "manifest.json"), maxRecipeBytes)
	if err != nil {
		return zero, err
	}
	if content["recipes/manifest.json"] != hashBytes(raw) {
		return zero, errors.New("setup recipe package digest mismatch")
	}
	r, err := decodeRecipes(raw)
	if err != nil {
		return zero, err
	}
	for rel, want := range r.Payload {
		b, err := readBounded(filepath.Join(packageRoot, filepath.FromSlash(rel)), maxRecipeBytes)
		if err != nil {
			return zero, err
		}
		if hashBytes(b) != want || content[rel] != want {
			return zero, fmt.Errorf("setup payload digest mismatch: %s", rel)
		}
	}
	return r, nil
}

func MakePlan(r Recipes, root, profile string) (Plan, error) {
	var p Plan
	if !filepath.IsAbs(root) || filepath.Clean(root) == filepath.VolumeName(root)+string(os.PathSeparator) {
		return p, errors.New("setup requires a dedicated absolute root, not a volume root")
	}
	if profile != "secrets" && profile != "mvp" {
		return p, errors.New("setup profile must be secrets or mvp")
	}
	if err := auditconfig.CheckPath(root, true); err != nil {
		return p, err
	}
	p = Plan{APIVersion: PlanVersion, Profile: profile, Root: filepath.Clean(root), RecipeDigest: r.Digest, RuntimeImage: r.RuntimeImage, Network: "explicit-preparation-only", TargetAccess: "none", Artifacts: []Artifact{}, Tools: []ToolRecipe{}, DynamicDatabases: []string{}, MinimumFreeBytes: 2 << 30}
	needed := map[string]bool{}
	for _, t := range r.Tools {
		if profile == "mvp" || t.ID == "gitleaks" {
			p.Tools = append(p.Tools, t)
			needed[t.Artifact] = true
		}
	}
	for _, a := range r.Artifacts {
		if needed[a.ID] || a.Purpose == "runtime" || (profile == "mvp" && a.Purpose == "reuse-dependency") {
			p.Artifacts = append(p.Artifacts, a)
			p.DownloadBytes += a.Bytes
		}
	}
	if profile == "mvp" {
		p.DynamicDatabases = []string{"grype-v6", "trivy-v2", "osv-Go"}
		p.MinimumFreeBytes = 12 << 30
	}
	sort.Slice(p.Artifacts, func(i, j int) bool { return p.Artifacts[i].ID < p.Artifacts[j].ID })
	sort.Slice(p.Tools, func(i, j int) bool { return p.Tools[i].ID < p.Tools[j].ID })
	b, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	p.Digest = "sha256:" + hashBytes(b)
	return p, nil
}

func safeRelative(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\\:\x00\r\n") && !strings.HasPrefix(s, "/") && filepath.ToSlash(filepath.Clean(s)) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../")
}
