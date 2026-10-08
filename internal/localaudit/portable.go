package localaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

func (p *preparedAudit) prepareToolchain(now time.Time) error {
	c := p.config
	p.configDigest = c.Digest()
	needed := map[string]bool{}
	var catalogExpiresAt time.Time
	if c.Version == auditconfig.PortableVersion {
		catalog, err := toolchain.LoadCatalog(c.ToolchainCatalog, now)
		if err != nil {
			return fmt.Errorf("toolchain catalog: %w", err)
		}
		p.configDigest = auditconfig.Digest([]byte(p.configDigest + "\x00" + catalog.Digest))
		catalogExpiresAt = catalog.ExpiresAt
		skipped := map[string]bool{}
		for _, node := range p.plan.Nodes {
			skipped[node.ID] = node.Status == "SKIPPED_NOT_APPLICABLE" || node.Status == "UNSUPPORTED"
		}
		all := map[string]toolchain.CatalogTool{}
		for _, t := range catalog.Tools {
			all[t.Record.ID] = t
		}
		p.catalogTools = map[string]toolchain.CatalogTool{}
		records := []toolchain.Record{}
		for _, m := range p.manifests {
			if skipped[m.ID] {
				continue
			}
			t, ok := all[m.ID]
			if !ok {
				if m.ID == "sbomqs" {
					p.sbomqsError = errors.New("sbomqs absent from approved catalog")
					continue
				}
				return fmt.Errorf("selected tool missing from catalog: %s", m.ID)
			}
			if t.Record.SourceLicense != m.SourceLicense || t.Record.Redistribution != m.Redistribution {
				return fmt.Errorf("catalog license metadata differs from manifest: %s", m.ID)
			}
			env := catalogEnvironment(t)
			if err := m.AllowsEnvironment(env); err != nil {
				return err
			}
			for _, item := range []struct{ root, path string }{{c.ToolchainRoot, t.Binary}, {c.ToolchainRoot, t.Database}, {c.ToolchainRoot, t.State}, {c.RulePackRoot, t.RulePack}} {
				if item.path == "" {
					continue
				}
				if item.root == "" {
					return errors.New("selected scanner requires rule_pack_root")
				}
				if err := auditconfig.CheckPath(filepath.Join(item.root, filepath.FromSlash(item.path)), false); err != nil {
					return fmt.Errorf("selected tool path %s: %w", m.ID, err)
				}
			}
			p.catalogTools[m.ID] = t
			needed[t.Provider] = true
			records = append(records, t.Record)
			if m.ID == "sbomqs" {
				p.sbomqs = &toolchain.OwnerApprovedTool{Record: t.Record, Binary: t.Binary, Owner: catalog.Owner, ApprovedAt: catalog.ApprovedAt, MetadataDigest: catalog.Digest}
			}
		}
		p.registry, err = toolchain.New(records)
		if err != nil {
			return err
		}
	} else {
		p.registry, p.sbomqs, p.sbomqsError = buildRegistry(c.ToolchainRoot)
		if p.sbomqs != nil {
			p.configDigest = auditconfig.Digest([]byte(p.configDigest + "\x00" + p.sbomqs.MetadataDigest))
		}
		needed["base"], needed["scancode"] = true, true
	}
	for _, kind := range []string{"base", "scancode"} {
		if !needed[kind] {
			continue
		}
		file := c.DockerBaseProvider
		if kind == "scancode" {
			file = c.DockerScanCodeProvider
		}
		provider, err := runner.LoadDockerProviderConfig(file, now)
		if err != nil {
			return fmt.Errorf("%s Docker provider: %w", kind, err)
		}
		if c.Version == auditconfig.Version {
			want := baseRuntime
			if kind == "scancode" {
				want = scancodeRuntime
			}
			if provider.RuntimeImage != want {
				return errors.New("legacy Docker provider runtime differs from approved PAO runtime")
			}
		}
		for _, t := range p.catalogTools {
			if t.Provider == kind && provider.RuntimeImage != "sha256:"+t.Record.RuntimeSHA256 {
				return errors.New("catalog runtime does not match selected Docker provider")
			}
		}
		data, err := json.Marshal(provider)
		if err != nil {
			return err
		}
		p.configDigest = auditconfig.Digest([]byte(p.configDigest + "\x00" + kind + "\x00" + auditconfig.Digest(data)))
		// Retain the original provider identity in the confirmation digest, then
		// narrow its launch authority to the catalog's earlier expiry. DockerHost
		// rechecks this deadline at both capability probing and launch time.
		if !catalogExpiresAt.IsZero() && catalogExpiresAt.Before(provider.RuntimeApproval.ExpiresAt) {
			provider.RuntimeApproval.ExpiresAt = catalogExpiresAt
		}
		if kind == "base" {
			p.baseHost = provider.Host()
		} else {
			p.scancodeHost = provider.Host()
		}
	}
	return nil
}

func catalogEnvironment(t toolchain.CatalogTool) map[string]string {
	env := map[string]string{}
	for k, v := range t.Record.DatabaseEnvironment {
		env[k] = v
	}
	for k, v := range t.Record.StateEnvironment {
		env[k] = v
	}
	return env
}

// catalogSpec completely replaces legacy identities and paths. No arbitrary argv,
// shell, network grant or output path can be supplied by a toolchain catalog.
func (p preparedAudit) catalogSpec(old runner.ExecutionSpec, m adapter.Manifest) (runner.ExecutionSpec, runner.DockerHost, error) {
	t, ok := p.catalogTools[m.ID]
	if !ok {
		return runner.ExecutionSpec{}, runner.DockerHost{}, errors.New("selected tool not approved")
	}
	join := func(root, rel string) string {
		if rel == "" {
			return ""
		}
		return filepath.Join(root, filepath.FromSlash(rel))
	}
	digest := func(s string) string {
		if s == "" {
			return ""
		}
		return "sha256:" + s
	}
	s := runner.ExecutionSpec{APIVersion: old.APIVersion, AdapterID: m.ID, ToolID: m.ID, ToolPath: join(p.config.ToolchainRoot, t.Binary), ToolDigest: digest(t.Record.SHA256), RuntimeDigest: digest(t.Record.RuntimeSHA256), TargetRoot: old.TargetRoot, TemporaryDir: old.TemporaryDir, InputPath: old.InputPath, ContainerName: old.ContainerName, Sandbox: old.Sandbox, OutputFile: old.OutputFile, OutputMediaType: old.OutputMediaType, AdditionalOutputs: old.AdditionalOutputs, TimeoutSeconds: m.TimeoutSeconds, MemoryMB: old.MemoryMB, Environment: catalogEnvironment(t), DatabasePath: join(p.config.ToolchainRoot, t.Database), DatabaseDigest: digest(t.Record.DatabaseSHA256), StatePath: join(p.config.ToolchainRoot, t.State), StateDigest: digest(t.Record.StateSHA256), StateEntrypoint: t.StateEntrypoint, RulePackPath: join(p.config.RulePackRoot, t.RulePack), RulePackDigest: digest(t.Record.RulePackSHA256), LicenseDataDigest: digest(t.Record.LicenseDataSHA256)}
	s.InputDigest = old.InputDigest
	s.MaxOutputBytes = min(m.MaxOutputBytes, int64(64<<20))
	args, err := runner.ManifestArguments(m, s)
	if err != nil {
		return s, runner.DockerHost{}, err
	}
	s.Arguments = args
	host := p.baseHost
	if t.Provider == "scancode" {
		host = p.scancodeHost
	}
	return s, host, s.Validate()
}
