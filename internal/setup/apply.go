package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

type preparedInstallation struct {
	Version    string                  `json:"version"`
	Profile    string                  `json:"profile"`
	PlanDigest string                  `json:"plan_digest"`
	Generation string                  `json:"generation"`
	State      string                  `json:"state"`
	Runtime    string                  `json:"runtime"`
	CLI        runner.PreparedCLI      `json:"cli"`
	Tools      []toolchain.CatalogTool `json:"tools"`
	PreparedAt time.Time               `json:"prepared_at"`
}

func nonce() string {
	var b [12]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func generation(p Plan) string {
	return filepath.Join(p.Root, "generations", strings.TrimPrefix(p.Digest, "sha256:"))
}
func loadPrepared(p Plan) (preparedInstallation, error) {
	var v preparedInstallation
	b, e := readBounded(filepath.Join(generation(p), "records", "prepared.json"), 2<<20)
	if e != nil {
		return v, e
	}
	if e = strictjson.Decode(b, &v, 2<<20); e != nil {
		return v, e
	}
	if v.Version != "pao.dev/prepared-installation/v1" || v.PlanDigest != p.Digest || v.Generation != generation(p) || v.State != filepath.Join(p.Root, "state") || !imageID(v.Runtime) || len(v.Tools) != len(p.Tools) {
		return v, errors.New("prepared generation identity differs")
	}
	wanted := map[string]ToolRecipe{}
	for _, t := range p.Tools {
		wanted[t.ID] = t
	}
	seen := map[string]bool{}
	for _, t := range v.Tools {
		want, ok := wanted[t.Record.ID]
		if !ok || seen[t.Record.ID] || t.Record.Version != want.Version || t.Record.SHA256 != want.BinarySHA256 || t.Record.SourceLicense != want.License || prefix(t.Record.RuntimeSHA256) != v.Runtime {
			return v, errors.New("prepared tool differs from the approved recipe")
		}
		seen[t.Record.ID] = true
		if !safeRelative(t.Binary) {
			return v, errors.New("unsafe prepared binary")
		}
		h, e := hashFile(filepath.Join(v.Generation, "tools", filepath.FromSlash(t.Binary)), 512<<20)
		if e != nil || h != strings.TrimPrefix(t.Record.SHA256, "sha256:") {
			return v, errors.New("prepared binary identity changed")
		}
		for _, x := range [][3]string{{t.State, t.Record.StateSHA256, "state"}, {t.Database, t.Record.DatabaseSHA256, "database"}, {t.RulePack, t.Record.RulePackSHA256, "rules"}} {
			if x[0] == "" {
				continue
			}
			if !safeRelative(x[0]) {
				return v, errors.New("unsafe prepared capsule")
			}
			path := filepath.Join(v.Generation, "tools", filepath.FromSlash(x[0]))
			if x[2] == "state" {
				e = runner.VerifyPreparedState(path, prefix(x[1]), t.Record.ID)
			} else if x[2] == "database" {
				e = runner.VerifyDatabaseSnapshot(path, prefix(x[1]), t.Record.ID)
				if e == nil {
					e = verifyPreparedDatabaseLayout(path, t.Record.ID)
				}
			} else {
				path = filepath.Join(v.Generation, "rules", filepath.FromSlash(x[0]))
				e = runner.VerifyInputCapsule(path, prefix(x[1]), t.Record.ID, "rule-pack")
			}
			if e != nil {
				return v, e
			}
		}
	}
	if e := freshPrepared(v, nowUTC()); e != nil {
		return v, e
	}
	return v, nil
}

func freshPrepared(v preparedInstallation, now time.Time) error {
	records := make([]toolchain.Record, 0, len(v.Tools))
	for _, t := range v.Tools {
		records = append(records, t.Record)
	}
	registry, e := toolchain.New(records)
	if e != nil {
		return e
	}
	for _, t := range v.Tools {
		requirement := toolchain.Requirement{ToolID: t.Record.ID, Capability: "setup-readiness", RequiresDatabase: t.Database != "", MaximumDatabaseAge: toolchain.DatabaseMaximumAge(t.Record.ID), RequiresState: t.State != "", MaximumStateAge: toolchain.MaximumPrerequisiteAge, RequiresRuntime: true, MaximumRuntimeAge: toolchain.MaximumPrerequisiteAge, RequiresRulePack: t.RulePack != "", MaximumRulePackAge: toolchain.MaximumPrerequisiteAge, RequiresLicenseData: t.Record.ID == "scancode", MaximumLicenseDataAge: toolchain.MaximumPrerequisiteAge}
		coverage := registry.Preflight(requirement, now)
		if coverage.Status != "AVAILABLE_NOT_STARTED" {
			return fmt.Errorf("%s: %s; prepare a fresh installation generation", coverage.ToolID, coverage.Reason)
		}
	}
	return nil
}

func apply(ctx context.Context, o options, r Recipes, p Plan, out io.Writer) (preparedInstallation, error) {
	var v preparedInstallation
	spacePath := p.Root
	for {
		if _, e := os.Stat(spacePath); e == nil {
			break
		}
		parent := filepath.Dir(spacePath)
		if parent == spacePath {
			return v, errors.New("installation volume is unavailable")
		}
		spacePath = parent
	}
	free, e := availableBytes(spacePath)
	if e != nil {
		return v, e
	}
	if free < uint64(p.MinimumFreeBytes) {
		return v, fmt.Errorf("installation needs at least %d free bytes; available %d", p.MinimumFreeBytes, free)
	}
	// Existing unrelated contents never become an installation implicitly.
	if entries, e := os.ReadDir(p.Root); e == nil && len(entries) > 0 {
		if _, e := readBounded(filepath.Join(p.Root, "setup-root.json"), 4096); e != nil {
			return v, errors.New("nonempty root is not an owned setup installation")
		}
	}
	if e := privateTree(p.Root); e != nil {
		return v, e
	}
	identity := filepath.Join(p.Root, "setup-root.json")
	if _, e := os.Lstat(identity); os.IsNotExist(e) {
		if e = writeOnce(identity, []byte("{\"version\":\"pao.dev/setup-root/v1\"}\n")); e != nil {
			return v, e
		}
	}
	gen := generation(p)
	state := filepath.Join(p.Root, "state")
	for _, path := range []string{filepath.Join(p.Root, "downloads"), filepath.Join(p.Root, "config"), filepath.Join(gen, "records"), filepath.Join(gen, "tools"), filepath.Join(gen, "rules"), filepath.Join(gen, "work")} {
		if e := privateTree(path); e != nil {
			return v, e
		}
	}
	if _, e := installation.Initialize(state); e != nil {
		return v, e
	}
	if e := installation.CheckReady(state); e != nil {
		return v, e
	}
	if _, e := os.Stat(filepath.Join(gen, "records", "prepared.json")); e == nil {
		return loadPrepared(p)
	}
	d, e := newDocker(ctx, o, state, filepath.Join(gen, "work"))
	if e != nil {
		return v, e
	}
	fmt.Fprintf(out, "Docker CLI: %s %s; endpoint=%s\n", d.cli.SourcePath, d.cli.SHA256, d.endpoint)
	downloads := map[string]string{}
	dl := newDownloader()
	cache := filepath.Join(p.Root, "downloads")
	for _, a := range p.Artifacts {
		fmt.Fprintf(out, "Preparing pinned artifact %s (%d bytes)\n", a.ID, a.Bytes)
		path, e := dl.fetch(ctx, a, cache, nil)
		if e != nil {
			return v, fmt.Errorf("%s: %w", a.ID, e)
		}
		downloads[a.ID] = path
	}
	runtimeID, e := d.buildRuntime(ctx, o, r, p, downloads, filepath.Join(gen, "work"))
	if e != nil {
		return v, e
	}
	inputs := filepath.Join(gen, "work", "inputs")
	recipe := filepath.Join(gen, "work", "recipe")
	if e = privateTree(inputs); e != nil {
		return v, e
	}
	if e = privateTree(recipe); e != nil {
		return v, e
	}
	lock := map[string]Artifact{}
	for _, a := range p.Artifacts {
		if e = copyExact(downloads[a.ID], filepath.Join(inputs, a.Filename), a.SHA256, a.Bytes); e != nil {
			return v, e
		}
		if a.ID == "opengrep" {
			if e = os.Chmod(filepath.Join(inputs, a.Filename), 0700); e != nil {
				return v, e
			}
		}
		lock[a.ID] = a
	}
	lockBytes, _ := json.Marshal(lock)
	if e = writeOrSame(filepath.Join(recipe, "inputs.json"), lockBytes); e != nil {
		return v, e
	}
	if e = copyExact(filepath.Join(o.packageRoot, "recipes", "prepare-state.py"), filepath.Join(recipe, "prepare-state.py"), r.Payload["recipes/prepare-state.py"], maxRecipeBytes); e != nil {
		return v, e
	}
	v = preparedInstallation{Version: "pao.dev/prepared-installation/v1", Profile: p.Profile, PlanDigest: p.Digest, Generation: gen, State: state, Runtime: runtimeID, CLI: d.cli, Tools: []toolchain.CatalogTool{}, PreparedAt: nowUTC()}
	for _, t := range p.Tools {
		fmt.Fprintf(out, "Preparing tool %s %s\n", t.ID, t.Version)
		installed, e := prepareTool(ctx, d, o, r, t, downloads[t.Artifact], runtimeID, gen, inputs, recipe)
		if e != nil {
			return v, fmt.Errorf("tool %s: %w", t.ID, e)
		}
		v.Tools = append(v.Tools, installed)
	}
	if p.Profile == "mvp" {
		fmt.Fprintln(out, "Preparing and verifying Grype, Trivy and OSV database snapshots; large databases may take several minutes.")
		databases, e := prepareDatabases(ctx, dl, cache, filepath.Join(gen, "tools"), func(ctx context.Context, source, destination string) error {
			return d.prepareGrype(ctx, runtimeID, gen, source, destination, v.Tools)
		})
		if e != nil {
			return v, e
		}
		for i := range v.Tools {
			if db, ok := databases[v.Tools[i].Record.ID]; ok {
				v.Tools[i].Database = db.Path
				v.Tools[i].Record.DatabaseSHA256 = strings.TrimPrefix(db.Digest, "sha256:")
				v.Tools[i].Record.DatabaseAt = db.At
				v.Tools[i].Record.DatabaseEnvironment = db.Environment
			}
		}
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	if e = writeOnce(filepath.Join(gen, "records", "prepared.json"), b); e != nil {
		return v, e
	}
	return loadPrepared(p)
}

func prepareTool(ctx context.Context, d dockerControl, o options, r Recipes, t ToolRecipe, artifact, runtimeID, gen, inputs, recipe string) (toolchain.CatalogTool, error) {
	var result toolchain.CatalogTool
	marker := filepath.Join(gen, "records", "tool-"+t.ID+".json")
	if b, e := readBounded(marker, 128<<10); e == nil {
		e = strictjson.Decode(b, &result, 128<<10)
		return result, e
	}
	leaf := t.ID + "/" + nonce()
	root := filepath.Join(gen, "tools", filepath.FromSlash(leaf))
	if e := privateTree(root); e != nil {
		return result, e
	}
	binary := filepath.Join(root, "bin", t.ID)
	if e := privateTree(filepath.Dir(binary)); e != nil {
		return result, e
	}
	if t.Format == "tar.gz" || t.Format == "scancode" {
		member := t.Member
		if t.Format == "scancode" {
			member = "scancode-toolkit-v32.5.0/scancode"
		}
		unpack := filepath.Join(root, "unpack")
		if e := privateTree(unpack); e != nil {
			return result, e
		}
		if e := extractTGZ(ctx, artifact, unpack, member, 4<<30); e != nil {
			return result, e
		}
		if e := copyExact(filepath.Join(unpack, filepath.FromSlash(member)), binary, t.BinarySHA256, 512<<20); e != nil {
			return result, e
		}
	} else {
		if e := copyExact(artifact, binary, t.BinarySHA256, 512<<20); e != nil {
			return result, e
		}
	}
	if e := os.Chmod(binary, 0700); e != nil {
		return result, e
	}
	now := nowUTC()
	result = toolchain.CatalogTool{Record: toolchain.Record{ID: t.ID, Version: t.Version, SHA256: t.BinarySHA256, SourceLicense: t.License, Redistribution: "user-installed-only", RuntimeSHA256: strings.TrimPrefix(runtimeID, "sha256:"), RuntimeAt: now}, Binary: leaf + "/bin/" + t.ID, Provider: "base"}
	if t.ID == "scancode" || t.ID == "reuse" || t.ID == "opengrep" {
		state := filepath.Join(root, "state")
		if e := privateTree(state); e != nil {
			return result, e
		}
		if e := d.prepareState(ctx, runtimeID, t.ID, inputs, recipe, state); e != nil {
			return result, e
		}
		digest, e := sealState(state, t.ID)
		if e != nil {
			return result, e
		}
		result.State = leaf + "/state"
		result.Record.StateSHA256 = strings.TrimPrefix(digest, "sha256:")
		result.Record.StateAt = now
		switch t.ID {
		case "scancode":
			result.StateEntrypoint = "venv/bin/scancode"
			result.Record.StateEnvironment = map[string]string{"PYTHONDONTWRITEBYTECODE": "1", "SCANCODE_CACHE": "/pao/out/scancode-cache", "SCANCODE_TEMP": "/pao/out/scancode-tmp"}
			result.Record.LicenseDataSHA256 = result.Record.StateSHA256
			result.Record.LicenseDataAt = now
		case "reuse":
			result.StateEntrypoint = "venv/bin/python"
		case "opengrep":
			result.Record.StateEnvironment = map[string]string{"HOME": "/pao/state", "TMPDIR": "/pao/state", "XDG_CACHE_HOME": "/pao/state", "SEMGREP_LOG_FILE": "/pao/out/semgrep.log"}
			result.RulePack = "opengrep/pao-baseline-v1"
			for rel, h := range r.Payload {
				if strings.HasPrefix(rel, "recipes/opengrep/") {
					dest := filepath.Join(gen, "rules", filepath.FromSlash(strings.TrimPrefix(rel, "recipes/")))
					if e := copyExact(filepath.Join(o.packageRoot, filepath.FromSlash(rel)), dest, h, maxRecipeBytes); e != nil {
						return result, e
					}
				}
			}
			result.Record.RulePackSHA256 = r.Payload["recipes/opengrep/pao-baseline-v1/pao-input-manifest.json"]
			result.Record.RulePackAt = now
		}
	}
	b, _ := json.Marshal(result)
	if e := writeOnce(marker, b); e != nil {
		return result, e
	}
	return result, nil
}
func sealState(root, id string) (string, error) {
	files, e := inventory(root, "pao-state-manifest.json")
	if e != nil {
		return "", e
	}
	if len(files) == 0 {
		return "", errors.New("prepared state is empty")
	}
	b, e := json.Marshal(struct {
		APIVersion string       `json:"api_version"`
		AdapterID  string       `json:"adapter_id"`
		Files      []fileDigest `json:"files"`
	}{"pao.dev/prepared-state/v1alpha1", id, files})
	if e != nil {
		return "", e
	}
	if e = writeOnce(filepath.Join(root, "pao-state-manifest.json"), b); e != nil {
		return "", e
	}
	return prefix(hashBytes(b)), nil
}
func writeOrSame(path string, b []byte) error {
	if old, e := readBounded(path, 2<<20); e == nil {
		if string(old) == string(b) {
			return nil
		}
		return errors.New("immutable setup record differs")
	}
	return writeOnce(path, b)
}

func writeConfiguration(o options, p preparedInstallation, verification runner.PreparationResult, imported *auditconfig.Config, approved bool) (string, error) {
	stamp := nonce()
	dir := filepath.Join(o.root, "config")
	if e := privateTree(dir); e != nil {
		return "", e
	}
	catalog := toolchain.Catalog{APIVersion: toolchain.CatalogVersion, Owner: "UNAPPROVED", Tools: p.Tools}
	provider := runner.DockerProviderConfig{APIVersion: runner.DockerProviderConfigVersion, DockerPath: p.CLI.Path, DockerSHA256: p.CLI.SHA256, RuntimeImage: p.Runtime, RuntimeApproval: runner.RuntimeApproval{ID: "UNAPPROVED", Owner: "UNAPPROVED", EvidenceDigest: verification.EvidenceDigest}}
	if approved {
		now := nowUTC()
		catalog.Owner = o.owner
		catalog.ApprovedAt = now
		catalog.ExpiresAt = now.Add(30 * 24 * time.Hour)
		provider.RuntimeApproval = runner.RuntimeApproval{ID: "setup-" + stamp, Owner: o.owner, EvidenceDigest: verification.EvidenceDigest, ExpiresAt: catalog.ExpiresAt}
	}
	catalogPath, providerPath := filepath.Join(dir, "catalog-"+stamp+".json"), filepath.Join(dir, "provider-"+stamp+".json")
	for path, v := range map[string]any{catalogPath: catalog, providerPath: provider} {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return "", e
		}
		if e = writeOnce(path, b); e != nil {
			return "", e
		}
	}
	config := auditconfig.Config{Version: auditconfig.InstallationVersion, Target: o.target, EvidenceBase: filepath.Join(o.root, "evidence"), ReportBase: filepath.Join(o.root, "reports"), ToolchainRoot: filepath.Join(p.Generation, "tools"), RulePackRoot: filepath.Join(p.Generation, "rules"), ManifestRoot: filepath.Join(o.packageRoot, "adapters"), DockerBaseProvider: providerPath, ToolchainCatalog: catalogPath, InstallationState: p.State}
	if imported != nil {
		config.EvidenceBase = imported.EvidenceBase
		config.ReportBase = imported.ReportBase
	}
	b, e := json.MarshalIndent(config, "", "  ")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "audit-"+stamp+".json")
	if e := config.ValidatePaths(path); e != nil {
		return "", e
	}
	// A generated configuration must meet doctor's private-root prerequisites.
	// Existing imported roots are validated, never chmod'ed or given new ACLs.
	for _, root := range []string{config.EvidenceBase, config.ReportBase} {
		if e := privateTree(root); e != nil {
			return "", fmt.Errorf("private output root %s: %w", root, e)
		}
	}
	return path, writeOnce(path, b)
}
