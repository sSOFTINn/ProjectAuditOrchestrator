package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/prompt"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

type options struct {
	root, profile, packageRoot, docker, importConfig, config, target, owner, confirmPlan string
	apply, verify                                                                        bool
}

// Command plans without writes or network. Only --apply or --verify can mutate
// the selected installation, and each needs an exact displayed confirmation.
func Command(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(errOut)
	o := options{}
	fs.StringVar(&o.root, "root", "", "dedicated absolute private installation root")
	fs.StringVar(&o.profile, "profile", "secrets", "secrets or mvp")
	fs.StringVar(&o.packageRoot, "package-root", "", "verified extracted package (defaults beside pao)")
	fs.StringVar(&o.docker, "docker-path", "", "installed Docker Desktop CLI (otherwise discover locally)")
	fs.StringVar(&o.importConfig, "import-config", "", "legacy configuration to import without changing the original")
	fs.StringVar(&o.config, "config", "", "existing v3 configuration for --verify")
	fs.StringVar(&o.target, "target", "", "local target path for the generated configuration; no target files are read")
	fs.StringVar(&o.owner, "owner", "", "real operator identity; final approval is still requested after verification")
	fs.StringVar(&o.confirmPlan, "confirm-plan", "", "exact displayed plan digest for noninteractive preparation only")
	fs.BoolVar(&o.apply, "apply", false, "prepare the displayed public inputs")
	fs.BoolVar(&o.verify, "verify", false, "rerun fixed synthetic isolation checks on an existing generation")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var imported *auditconfig.Config
	if o.config != "" {
		if !o.verify || o.importConfig != "" {
			fmt.Fprintln(errOut, "--config is supported only with --verify")
			return 2
		}
		raw, e := readBounded(o.config, auditconfig.MaxBytes)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
		c, e := auditconfig.Decode(raw)
		if e != nil || c.Version != auditconfig.InstallationVersion {
			fmt.Fprintln(errOut, "--verify --config requires a valid v3 configuration")
			return 2
		}
		inferred := filepath.Dir(c.InstallationState)
		if o.root != "" && o.root != inferred {
			fmt.Fprintln(errOut, "--root differs from configuration installation")
			return 2
		}
		o.root = inferred
		var prepared preparedInstallation
		raw, e = readBounded(filepath.Join(filepath.Dir(c.ToolchainRoot), "records", "prepared.json"), 2<<20)
		if e != nil || json.Unmarshal(raw, &prepared) != nil {
			fmt.Fprintln(errOut, "configuration has no prepared generation")
			return 2
		}
		o.profile = prepared.Profile
		imported = &c
	}
	if fs.NArg() != 0 || o.root == "" || o.apply && o.verify {
		fmt.Fprintln(errOut, "setup requires --root and one of plan, --apply or --verify")
		return 2
	}
	if o.packageRoot == "" {
		exe, e := os.Executable()
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
		o.packageRoot = filepath.Dir(exe)
	}
	r, e := LoadRecipes(o.packageRoot)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	if buildinfo.RecipesSHA256 != "" && strings.TrimPrefix(buildinfo.RecipesSHA256, "sha256:") != r.Digest {
		fmt.Fprintln(errOut, "bundled recipe differs from executable build identity")
		return 2
	}
	p, e := MakePlan(r, o.root, o.profile)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	if o.importConfig != "" {
		raw, e := readBounded(o.importConfig, auditconfig.MaxBytes)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
		c, e := auditconfig.Decode(raw)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
		if auditconfig.Overlap(c.Target, p.Root) {
			fmt.Fprintln(errOut, "installation root overlaps the imported target")
			return 2
		}
		imported = &c
	}
	if imported != nil && o.target == "" {
		o.target = imported.Target
	}
	if o.target != "" {
		if e := validateTargetPlacement(o.target, o.root, o.packageRoot); e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
	}
	if !o.apply && !o.verify {
		if e := json.NewEncoder(out).Encode(p); e != nil {
			return 2
		}
		return 0
	}
	if buildinfo.RecipesSHA256 == "" || buildinfo.ProbeSHA256 == "" || buildinfo.SandboxSHA256 == "" {
		fmt.Fprintln(errOut, "apply/verify requires the versioned package with embedded recipe, probe and sandbox hashes")
		return 2
	}
	input := bufio.NewReader(io.LimitReader(in, 64<<10))
	if o.target == "" {
		fmt.Fprint(out, "Local project path for the audit (contents are not read during setup):\n> ")
		line, err := prompt.Line(ctx, input)
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(errOut, "Setup input cancelled or unavailable; no preparation started.")
			return 2
		}
		o.target = strings.TrimSpace(line)
	}
	if e := validateTargetPlacement(o.target, o.root, o.packageRoot); e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	if e := auditconfig.CheckPath(o.target, false); e != nil {
		fmt.Fprintln(errOut, "target path:", e)
		return 2
	}
	if info, e := os.Lstat(o.target); e != nil || !info.IsDir() {
		fmt.Fprintln(errOut, "target must be an existing directory")
		return 2
	}
	action := "prepare"
	if o.verify {
		action = "verify"
	}
	fmt.Fprintf(out, "%s profile=%s root=%s recipe=%s pinned_bytes=%d target_access=none\n", action, p.Profile, p.Root, p.RecipeDigest, p.DownloadBytes)
	fmt.Fprintf(out, "Public inputs and license references:\n")
	for _, a := range p.Artifacts {
		fmt.Fprintf(out, "%s %s sha256:%s %d bytes license=%s\n", a.ID, a.URL, a.SHA256, a.Bytes, a.License)
	}
	fmt.Fprintf(out, "Runtime: %s; source/terms: %s %s\n", r.RuntimeImage, r.RuntimeSource, r.RuntimeLicenseURL)
	for _, t := range p.Tools {
		fmt.Fprintf(out, "Tool terms: %s %s\n", t.ID, t.LicenseURL)
	}
	if o.confirmPlan != p.Digest {
		if o.confirmPlan != "" {
			fmt.Fprintln(errOut, "confirmation digest differs from this plan")
			return 2
		}
		if !confirm(ctx, input, out, "PREPARE "+p.Digest) {
			fmt.Fprintln(errOut, "No preparation confirmation; no installation changes made.")
			return 2
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Setup cancelled; no preparation started.")
		return 2
	}
	var installed preparedInstallation
	if o.verify {
		installed, e = loadPrepared(p)
	} else {
		installed, e = apply(ctx, o, r, p, out)
	}
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	fmt.Fprintln(out, "Checking container isolation with the bundled synthetic probes; no audit target is scanned.")
	result, e := verify(ctx, o, installed)
	if e != nil {
		fmt.Fprintln(errOut, "Verification failed; approval was not created:", e)
		return 2
	}
	evidence, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	evidencePath := filepath.Join(installed.Generation, "records", "verification-"+nonce()+".json")
	if e = writeOnce(evidencePath, evidence); e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	fmt.Fprintf(out, "Synthetic verification: %s; evidence=%s\n", result.Status, result.EvidenceDigest)
	fmt.Fprintf(out, "Prepared runtime: %s\nPrepared inventory: %s\n", installed.Runtime, filepath.Join(installed.Generation, "records", "prepared.json"))
	for _, tool := range installed.Tools {
		fmt.Fprintf(out, "%s %s binary=sha256:%s state=%s database=%s database_at=%s rules=%s\n", tool.Record.ID, tool.Record.Version, tool.Record.SHA256, tool.Record.StateSHA256, tool.Record.DatabaseSHA256, tool.Record.DatabaseAt.Format(time.RFC3339), tool.Record.RulePackSHA256)
	}
	if e = auditconfig.CheckPath(o.target, false); e != nil {
		fmt.Fprintln(errOut, "target path:", e)
		return 2
	}
	if o.owner == "" {
		fmt.Fprint(out, "Operator name for the review (blank leaves drafts unapproved):\n> ")
		line, err := prompt.Line(ctx, input)
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(errOut, "Setup input cancelled or unavailable; prepared evidence retained without approval.")
			return 2
		}
		o.owner = strings.TrimSpace(line)
	}
	// Neither a name nor --confirm-plan grants approval of bytes that have not
	// yet been prepared. The digest below binds the completed catalogue and probe.
	approvalDigest := approvalIdentity(installed, result)
	approved := false
	if validOwner(o.owner) {
		fmt.Fprintf(out, "Review the prepared tools, licenses, public database scope and verification above. Approval expires in 30 days.\n")
		approved = confirm(ctx, input, out, "APPROVE "+approvalDigest+" AS "+o.owner)
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Setup cancelled; prepared evidence retained without approval.")
		return 2
	}
	config, e := writeConfiguration(o, installed, result, imported, approved)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 2
	}
	status := "PREPARED_NOT_APPROVED"
	if approved {
		status = "READY"
	}
	fmt.Fprintf(out, "%s config=%s\n", status, config)
	if !approved {
		fmt.Fprintf(out, "No approval identity or dates were fabricated. Re-run setup --verify --config %q --owner <your-name> to review and approve.\n", config)
		return 3
	}
	return 0
}

// Plan validates only the supplied path text. Apply/verify additionally checks
// existing ancestors before preparation, without opening target contents.
func validateTargetPlacement(path, root, packageRoot string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\x00\r\n") || auditconfig.Overlap(path, root) || auditconfig.Overlap(path, packageRoot) {
		return errors.New("target must be a clean absolute local path separate from installation and package")
	}
	return nil
}

func validOwner(s string) bool {
	v := strings.ToUpper(strings.TrimSpace(s))
	return v != "" && v != "UNAPPROVED" && v != "UNKNOWN" && v != "PENDING" && !strings.HasPrefix(v, "REPLACE_") && !strings.ContainsAny(s, "\x00\r\n")
}
func confirm(ctx context.Context, in *bufio.Reader, out io.Writer, phrase string) bool {
	fmt.Fprintf(out, "Type exactly: %s\n> ", phrase)
	s, e := prompt.Line(ctx, in)
	return (e == nil || errors.Is(e, io.EOF)) && strings.TrimSpace(s) == phrase
}
func verify(ctx context.Context, o options, p preparedInstallation) (runner.PreparationResult, error) {
	probe := filepath.Join(o.packageRoot, "pao-probe-linux-amd64")
	sandbox := filepath.Join(o.packageRoot, "pao-sandbox-linux-amd64")
	if buildinfo.ProbeSHA256 == "" || buildinfo.SandboxSHA256 == "" {
		return runner.PreparationResult{}, errors.New("versioned package must bind the bundled probe and sandbox digests")
	}
	return runner.VerifyPreparation(ctx, runner.PreparationSpec{DockerPath: p.CLI.Path, DockerSHA256: p.CLI.SHA256, RuntimeImage: p.Runtime, InstallationState: p.State, ProbePath: probe, ProbeSHA256: prefix(buildinfo.ProbeSHA256), SandboxPath: sandbox, SandboxSHA256: prefix(buildinfo.SandboxSHA256), Confirmed: true})
}
func prefix(s string) string {
	if s == "" {
		return ""
	}
	return "sha256:" + strings.TrimPrefix(s, "sha256:")
}
func approvalIdentity(p preparedInstallation, r runner.PreparationResult) string {
	b, _ := json.Marshal(struct {
		Installation preparedInstallation
		Verification runner.PreparationResult
	}{p, r})
	return prefix(hashBytes(b))
}
func nowUTC() time.Time { return time.Now().UTC() }
