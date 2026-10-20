package toolchain

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

const CatalogVersion = "pao.dev/toolchain-catalog/v1"
const catalogLimit = 128 << 10

// Catalog is private operator approval, not an installer or an executable plugin.
// Paths are relative to the configured toolchain or rule-pack root. Arguments,
// output locations and isolation policy remain controlled by PAO's manifests.
type Catalog struct {
	APIVersion string        `json:"api_version"`
	Owner      string        `json:"owner"`
	ApprovedAt time.Time     `json:"approved_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Tools      []CatalogTool `json:"tools"`
	Digest     string        `json:"-"`
}

type CatalogTool struct {
	Record          Record `json:"record"`
	Binary          string `json:"binary"`
	Provider        string `json:"provider"`
	Database        string `json:"database,omitempty"`
	State           string `json:"state,omitempty"`
	StateEntrypoint string `json:"state_entrypoint,omitempty"`
	RulePack        string `json:"rule_pack,omitempty"`
}

func LoadCatalog(file string, now time.Time) (Catalog, error) {
	var c Catalog
	if err := auditconfig.CheckPath(file, false); err != nil {
		return c, err
	}
	f, err := os.Open(file)
	if err != nil {
		return c, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() {
		return c, errors.New("catalog must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, catalogLimit+1))
	if err != nil {
		return c, err
	}
	if err := strictjson.Decode(raw, &c, catalogLimit); err != nil {
		return c, err
	}
	if c.APIVersion != CatalogVersion {
		return c, errors.New(`catalog field "api_version" must be pao.dev/toolchain-catalog/v1`)
	}
	if strings.TrimSpace(c.Owner) == "" || strings.EqualFold(strings.TrimSpace(c.Owner), "UNAPPROVED") || strings.ContainsAny(c.Owner, "\x00\r\n") {
		return c, errors.New(`catalog field "owner" requires an explicit approval after reviewing the exact tools and terms; UNAPPROVED is not approval`)
	}
	if c.ApprovedAt.IsZero() || c.ApprovedAt.After(now) {
		return c, errors.New(`catalog field "approved_at" must record an actual approval time that is not in the future`)
	}
	if !c.ExpiresAt.After(now) {
		return c, errors.New(`catalog field "expires_at" is missing or expired; review current prerequisites before creating a new approval`)
	}
	if c.ExpiresAt.Sub(c.ApprovedAt) > MaximumPrerequisiteAge {
		return c, errors.New(`catalog field "expires_at" must be within 90 days of "approved_at"; shorter prerequisite freshness limits still apply`)
	}
	if len(c.Tools) == 0 || len(c.Tools) > 10 {
		return c, errors.New(`catalog field "tools" requires 1..10 explicitly reviewed tool records`)
	}
	records := make([]Record, 0, len(c.Tools))
	for _, tool := range c.Tools {
		if err := tool.validate(); err != nil {
			return c, err
		}
		records = append(records, tool.Record)
	}
	if _, err := New(records); err != nil {
		return c, err
	}
	c.Digest = auditconfig.Digest(raw)
	return c, nil
}

func SafeRelative(value string) bool {
	return value != "" && value != "." && value != ".." && path.Clean(value) == value && !strings.HasPrefix(value, "../") && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\:\x00\r\n")
}

func (t CatalogTool) validate() error {
	switch t.Record.ID {
	case "syft", "sbomqs", "grype", "osv-scanner", "trivy", "gitleaks", "scancode", "reuse", "opengrep", "zizmor":
	default:
		return errors.New("unsupported catalog tool")
	}
	if !SafeRelative(t.Binary) || (t.Provider != "base" && t.Provider != "scancode") || t.Record.RuntimeSHA256 == "" || t.Record.Redistribution != "user-installed-only" {
		return errors.New("catalog requires safe binary, provider, pinned runtime and user-installed-only tool")
	}
	for _, p := range []string{t.Database, t.State, t.StateEntrypoint, t.RulePack} {
		if p != "" && !SafeRelative(p) {
			return errors.New("unsafe catalog relative path")
		}
	}
	for _, pair := range [][2]string{{t.Database, t.Record.DatabaseSHA256}, {t.State, t.Record.StateSHA256}, {t.RulePack, t.Record.RulePackSHA256}} {
		if (pair[0] == "") != (pair[1] == "") {
			return errors.New("catalog path and digest must be supplied together")
		}
	}
	if t.StateEntrypoint != "" && t.State == "" {
		return errors.New("state entrypoint requires prepared state")
	}
	if (t.Record.ID == "grype" || t.Record.ID == "osv-scanner" || t.Record.ID == "trivy") && t.Database == "" {
		return errors.New("scanner requires a pinned database")
	}
	if (t.Record.ID == "scancode" || t.Record.ID == "reuse" || t.Record.ID == "opengrep") && t.State == "" {
		return errors.New("scanner requires pinned prepared state")
	}
	if (t.Record.ID == "scancode" || t.Record.ID == "reuse") && t.StateEntrypoint == "" {
		return errors.New("scanner requires a state entrypoint")
	}
	if t.Record.ID == "opengrep" && t.RulePack == "" {
		return errors.New("opengrep requires pinned rule pack")
	}
	if t.Record.ID == "scancode" && t.Record.LicenseDataSHA256 == "" {
		return errors.New("scancode requires pinned license data")
	}
	return nil
}
