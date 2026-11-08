package setup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

func newReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func recipeFixture(t *testing.T) (string, Recipes) {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tools", "public-package"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(source, "recipes", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeRecipes(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "recipes"), 0700); err != nil {
		t.Fatal(err)
	}
	content := map[string]string{"recipes/manifest.json": hashBytes(raw)}
	if err := os.WriteFile(filepath.Join(root, "recipes", "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for rel, want := range r.Payload {
		b, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if hashBytes(b) != want {
			t.Fatalf("stale recipe payload hash: %s", rel)
		}
		dest := filepath.Join(root, filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dest, b, 0600); err != nil {
			t.Fatal(err)
		}
		content[rel] = want
	}
	manifest, _ := json.Marshal(content)
	if err := os.WriteFile(filepath.Join(root, "PACKAGE-CONTENTS.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	return root, r
}

func TestDefaultPlanDoesNotCreateInstallationOrReadTarget(t *testing.T) {
	pkg, r := recipeFixture(t)
	root := filepath.Join(t.TempDir(), "not-created")
	var out, errs bytes.Buffer
	code := Command(context.Background(), []string{"--root", root, "--package-root", pkg, "--profile", "secrets", "--target", filepath.Join(filepath.Dir(root), "unavailable-target")}, strings.NewReader(""), &out, &errs)
	if code != 0 {
		t.Fatalf("plan failed %d: %s", code, errs.String())
	}
	if _, e := os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("plan created installation")
	}
	var p Plan
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Tools) != 1 || p.Tools[0].ID != "gitleaks" || p.TargetAccess != "none" || p.RecipeDigest != r.Digest {
		t.Fatalf("unsafe secrets plan: %#v", p)
	}
}

func TestPlanPinsProfilesAndRejectsUnsafePaths(t *testing.T) {
	_, r := recipeFixture(t)
	root := filepath.Join(t.TempDir(), "installation")
	a, e := MakePlan(r, root, "mvp")
	if e != nil {
		t.Fatal(e)
	}
	b, e := MakePlan(r, root, "mvp")
	if e != nil || a.Digest != b.Digest {
		t.Fatal("unstable plan identity")
	}
	if len(a.Tools) != 10 || len(a.DynamicDatabases) != 3 {
		t.Fatal("incomplete mvp plan")
	}
	for _, p := range []string{"relative", filepath.VolumeName(root) + string(os.PathSeparator)} {
		if _, e := MakePlan(r, p, "mvp"); e == nil {
			t.Fatalf("admitted unsafe root %q", p)
		}
	}
	if _, e := MakePlan(r, root, "all"); e == nil {
		t.Fatal("admitted unowned profile")
	}
}

func TestPackageRecipeTamperingFailsBeforeWrites(t *testing.T) {
	pkg, _ := recipeFixture(t)
	path := filepath.Join(pkg, "recipes", "prepare-state.py")
	if e := os.WriteFile(path, []byte("altered"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadRecipes(pkg); e == nil {
		t.Fatal("admitted altered recipe payload")
	}
}

func TestConfirmationRequiresExactDigestAndOwner(t *testing.T) {
	var out bytes.Buffer
	if confirm(context.Background(), newReader("yes\n"), &out, "PREPARE sha256:abc") {
		t.Fatal("generic yes granted scoped preparation")
	}
	if !confirm(context.Background(), newReader("APPROVE sha256:abc AS Alice\n"), &out, "APPROVE sha256:abc AS Alice") {
		t.Fatal("exact approval refused")
	}
	for _, owner := range []string{"", "UNAPPROVED", "UNKNOWN", "x\ny", "REPLACE_NAME"} {
		if validOwner(owner) {
			t.Fatalf("placeholder owner admitted: %q", owner)
		}
	}
}

func TestArchiveRefusesTraversalLinksAndAliases(t *testing.T) {
	cases := [][]tar.Header{
		{{Name: "../escape", Mode: 0600, Size: 1}},
		{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		{{Name: "File", Mode: 0600, Size: 1}, {Name: "file", Mode: 0600, Size: 1}},
		{{Name: "safe", Mode: 0600, Size: 1}, {Name: "x", Typeflag: tar.TypeLink, Linkname: "safe"}},
	}
	for _, headers := range cases {
		root := t.TempDir()
		archive := filepath.Join(root, "input.tgz")
		f, e := os.Create(archive)
		if e != nil {
			t.Fatal(e)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for _, h := range headers {
			if e = tw.WriteHeader(&h); e != nil {
				t.Fatal(e)
			}
			if h.Size > 0 {
				_, _ = tw.Write([]byte("x"))
			}
		}
		_ = tw.Close()
		_ = gz.Close()
		_ = f.Close()
		dest := filepath.Join(root, "out")
		if e = privateTree(dest); e != nil {
			t.Fatal(e)
		}
		if e = extractTGZ(context.Background(), archive, dest, "", 1024); e == nil {
			t.Fatalf("unsafe archive accepted: %#v", headers)
		}
	}
}

func TestPreparedStateBindsCompleteBytes(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "data"), []byte("public-data"), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := sealState(root, "reuse")
	if e != nil {
		t.Fatal(e)
	}
	if e = runner.VerifyPreparedState(root, h, "reuse"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "data"), []byte("altered"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = runner.VerifyPreparedState(root, h, "reuse"); e == nil {
		t.Fatal("changed prepared bytes accepted")
	}
}

func TestDraftConfigurationNeverFabricatesApproval(t *testing.T) {
	root := t.TempDir()
	o := options{root: root, packageRoot: filepath.Join(root, "package"), target: filepath.Join(t.TempDir(), "target")}
	p := preparedInstallation{Generation: filepath.Join(root, "generations", "synthetic"), State: filepath.Join(root, "state"), Runtime: prefix(strings.Repeat("a", 64))}
	for _, dir := range []string{o.target, filepath.Join(o.packageRoot, "adapters"), filepath.Join(p.Generation, "tools"), filepath.Join(p.Generation, "rules"), p.State} {
		if e := privateTree(dir); e != nil {
			t.Fatal(e)
		}
	}
	c, e := writeConfiguration(o, p, runner.PreparationResult{EvidenceDigest: prefix(strings.Repeat("b", 64))}, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(c)
	if e != nil {
		t.Fatal(e)
	}
	config, e := auditconfig.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	if config.Version != auditconfig.InstallationVersion || config.Target != o.target {
		t.Fatal("config path/version incorrect")
	}
	for _, path := range []string{config.EvidenceBase, config.ReportBase} {
		if e := installation.ValidatePrivatePath(path, true); e != nil {
			t.Fatalf("generated config has no ready private output root: %v", e)
		}
	}
	raw, e = os.ReadFile(config.ToolchainCatalog)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte(`"owner": "UNAPPROVED"`)) || bytes.Contains(raw, []byte(`"approved_at": "2026`)) {
		t.Fatal("draft fabricated approval")
	}
}

func TestImportedPrivateOutputRootsArePreserved(t *testing.T) {
	root := t.TempDir()
	o := options{root: root, packageRoot: filepath.Join(root, "package"), target: filepath.Join(t.TempDir(), "target")}
	p := preparedInstallation{Generation: filepath.Join(root, "generations", "synthetic"), State: filepath.Join(root, "state"), Runtime: prefix(strings.Repeat("a", 64))}
	imported := &auditconfig.Config{EvidenceBase: filepath.Join(t.TempDir(), "evidence"), ReportBase: filepath.Join(t.TempDir(), "reports")}
	for _, dir := range []string{o.target, filepath.Join(o.packageRoot, "adapters"), filepath.Join(p.Generation, "tools"), filepath.Join(p.Generation, "rules"), p.State, imported.EvidenceBase, imported.ReportBase} {
		if e := privateTree(dir); e != nil {
			t.Fatal(e)
		}
	}
	before := map[string]os.FileMode{}
	for _, dir := range []string{imported.EvidenceBase, imported.ReportBase} {
		info, e := os.Stat(dir)
		if e != nil {
			t.Fatal(e)
		}
		before[dir] = info.Mode()
		if e = os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("retain"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	path, e := writeConfiguration(o, p, runner.PreparationResult{}, imported, false)
	if e != nil {
		t.Fatal(e)
	}
	config, e := auditconfig.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if config.EvidenceBase != imported.EvidenceBase || config.ReportBase != imported.ReportBase {
		t.Fatal("imported output roots replaced")
	}
	for dir, mode := range before {
		info, e := os.Stat(dir)
		if e != nil || info.Mode() != mode {
			t.Fatal("existing output mode changed")
		}
		b, e := os.ReadFile(filepath.Join(dir, "existing.txt"))
		if e != nil || string(b) != "retain" {
			t.Fatal("existing output contents changed")
		}
	}
}
