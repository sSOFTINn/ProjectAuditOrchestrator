package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
)

func TestTargetPlacementFailsBeforePreparation(t *testing.T) {
	pkg, _ := recipeFixture(t)
	base := t.TempDir()
	root := filepath.Join(base, "installation")
	for name, target := range map[string]string{
		"relative":            "relative-target",
		"installation":        root,
		"inside-installation": filepath.Join(root, "target"),
		"installation-parent": base,
		"package":             pkg,
		"inside-package":      filepath.Join(pkg, "target"),
		"unclean":             base + string(os.PathSeparator) + "target" + string(os.PathSeparator) + "..",
		"line-break":          filepath.Join(base, "target\ninvalid"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"plan", "--apply", "--verify"} {
				args := []string{"--root", root, "--package-root", pkg, "--target", target}
				if mode != "plan" {
					args = append(args, mode)
				}
				var out, errs bytes.Buffer
				if code := Command(context.Background(), args, strings.NewReader(""), &out, &errs); code != 2 || !strings.Contains(errs.String(), "target must be") {
					t.Fatalf("%s did not reject target before preparation: code=%d out=%q err=%q", mode, code, out.String(), errs.String())
				}
				if _, err := os.Lstat(root); !os.IsNotExist(err) {
					t.Fatal("target rejection created installation")
				}
			}
		})
	}
}

func TestImportedTargetPlacementFailsBeforePreparation(t *testing.T) {
	pkg, _ := recipeFixture(t)
	base := t.TempDir()
	root := filepath.Join(base, "installation")
	c := auditconfig.Config{Version: auditconfig.PortableVersion, Target: filepath.Join(pkg, "target"), EvidenceBase: filepath.Join(base, "evidence"), ReportBase: filepath.Join(base, "reports"), ToolchainRoot: filepath.Join(base, "tools"), ManifestRoot: filepath.Join(base, "manifests"), ToolchainCatalog: filepath.Join(base, "catalog.json")}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "import.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := Command(context.Background(), []string{"--root", root, "--package-root", pkg, "--import-config", path, "--apply"}, strings.NewReader(""), &out, &errs)
	if code != 2 || !strings.Contains(errs.String(), "target must be") {
		t.Fatalf("import target did not fail before preparation: code=%d out=%q err=%q", code, out.String(), errs.String())
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("import target rejection created installation")
	}
}

func TestInteractiveTargetFailsBeforePreparation(t *testing.T) {
	pkg, r := recipeFixture(t)
	root := filepath.Join(t.TempDir(), "installation")
	previousRecipes, previousProbe, previousSandbox := buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256
	buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = r.Digest, strings.Repeat("a", 64), strings.Repeat("b", 64)
	t.Cleanup(func() {
		buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = previousRecipes, previousProbe, previousSandbox
	})
	var out, errs bytes.Buffer
	code := Command(context.Background(), []string{"--root", root, "--package-root", pkg, "--apply"}, strings.NewReader(root+"\n"), &out, &errs)
	if code != 2 || !strings.Contains(errs.String(), "target must be") || strings.Contains(out.String(), "PREPARE ") {
		t.Fatalf("interactive target did not fail before preparation: code=%d out=%q err=%q", code, out.String(), errs.String())
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("interactive target rejection created installation")
	}
}

func TestTargetFileFailsBeforePreparation(t *testing.T) {
	pkg, r := recipeFixture(t)
	base := t.TempDir()
	root, target := filepath.Join(base, "installation"), filepath.Join(base, "target.txt")
	if err := os.WriteFile(target, []byte("synthetic target is not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	previousRecipes, previousProbe, previousSandbox := buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256
	buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = r.Digest, strings.Repeat("a", 64), strings.Repeat("b", 64)
	t.Cleanup(func() {
		buildinfo.RecipesSHA256, buildinfo.ProbeSHA256, buildinfo.SandboxSHA256 = previousRecipes, previousProbe, previousSandbox
	})
	var out, errs bytes.Buffer
	code := Command(context.Background(), []string{"--root", root, "--package-root", pkg, "--target", target, "--apply"}, strings.NewReader(""), &out, &errs)
	if code != 2 || !strings.Contains(errs.String(), "target must be an existing directory") || strings.Contains(out.String(), "PREPARE ") {
		t.Fatalf("target file did not fail before preparation: code=%d out=%q err=%q", code, out.String(), errs.String())
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("target file rejection created installation")
	}
}
