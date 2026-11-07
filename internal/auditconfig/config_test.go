package auditconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Config, string) {
	t.Helper()
	root := t.TempDir()
	c := Config{Version: Version, Target: filepath.Join(root, "project"), EvidenceBase: filepath.Join(root, "evidence"), ReportBase: filepath.Join(root, "reports"), ToolchainRoot: filepath.Join(root, "tools"), RulePackRoot: filepath.Join(root, "rules"), ManifestRoot: filepath.Join(root, "manifests"), DockerBaseProvider: filepath.Join(root, "config", "base.json"), DockerScanCodeProvider: filepath.Join(root, "config", "scancode.json")}
	for _, p := range []string{c.Target, c.ToolchainRoot, c.RulePackRoot, c.ManifestRoot, filepath.Join(root, "config")} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{c.DockerBaseProvider, c.DockerScanCodeProvider} {
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c, filepath.Join(root, "config", "audit.json")
}

func TestStrictJSONRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	c, _ := fixture(t)
	data, _ := json.Marshal(c)
	valid := string(data)
	for name, bad := range map[string]string{
		"duplicate":         strings.Replace(valid, `"version":`, `"version":"other","version":`, 1),
		"escaped duplicate": strings.Replace(valid, `"version":`, `"\u0076ersion":"other","version":`, 1),
		"case alias":        strings.Replace(valid, `"target":`, `"Target":`, 1),
		"network grant":     strings.Replace(valid, `"version":`, `"allow_network":"true","version":`, 1),
		"profile default":   strings.Replace(valid, `"version":`, `"profile":"mvp","version":`, 1),
		"null":              strings.Replace(valid, `"version":"`+Version+`"`, `"version":null`, 1),
		"nested":            strings.Replace(valid, `"version":"`+Version+`"`, `"version":{}`, 1),
		"trailing":          valid + ` {}`, "empty": "{}", "oversize": strings.Repeat(" ", MaxBytes) + valid,
		"invalid utf8": string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(bad)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	decoded, err := Decode(data)
	if err != nil || decoded != c {
		t.Fatalf("valid JSON: %v", err)
	}
}

func TestLoadAndSeparationBeforeOutputCreation(t *testing.T) {
	c, path := fixture(t)
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"inside target":          func(v *Config) { v.EvidenceBase = filepath.Join(v.Target, "output") },
		"target inside evidence": func(v *Config) { v.EvidenceBase = filepath.Dir(v.Target) },
		"report inside evidence": func(v *Config) { v.ReportBase = filepath.Join(v.EvidenceBase, "report") },
		"relative":               func(v *Config) { v.Target = "project" },
		"trusted target overlap": func(v *Config) { v.ManifestRoot = v.Target },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			if bad.ValidatePaths(path) == nil {
				t.Fatal("accepted unsafe paths")
			}
		})
	}
	if err := c.ValidatePaths(filepath.Join(c.Target, "audit.json")); err == nil {
		t.Fatal("accepted target config")
	}
	for _, p := range []string{c.EvidenceBase, c.ReportBase} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("validation wrote output")
		}
	}
}

func TestRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	if CheckPath(filepath.Join(link, "future"), true) == nil {
		t.Fatal("accepted symlink ancestor")
	}
}

func TestDigestStableAcrossJSONFormatting(t *testing.T) {
	c, _ := fixture(t)
	compact, _ := json.Marshal(c)
	pretty, _ := json.MarshalIndent(c, "", "  ")
	a, _ := Decode(compact)
	b, _ := Decode(pretty)
	if a.Digest() != b.Digest() {
		t.Fatal("formatting changed effective identity")
	}
	b.Target += "other"
	if a.Digest() == b.Digest() {
		t.Fatal("target not bound")
	}
}

func TestPortableConfigRequiresCatalogButAllowsOmittedUnusedDependencies(t *testing.T) {
	c, _ := fixture(t)
	c.Version = PortableVersion
	c.ToolchainCatalog = filepath.Join(filepath.Dir(c.DockerBaseProvider), "catalog.json")
	c.RulePackRoot, c.DockerBaseProvider, c.DockerScanCodeProvider = "", "", ""
	raw, _ := json.Marshal(c)
	if decoded, err := Decode(raw); err != nil || decoded != c {
		t.Fatalf("v2 rejected: %v", err)
	}
	for _, key := range []string{"rule_pack_root", "docker_base_provider", "docker_scancode_provider"} {
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		delete(fields, key)
		data, _ := json.Marshal(fields)
		if _, err := Decode(data); err != nil {
			t.Fatalf("unused %s required: %v", key, err)
		}
	}
	c.ToolchainCatalog = ""
	raw, _ = json.Marshal(c)
	if _, err := Decode(raw); err == nil {
		t.Fatal("catalog-free v2 accepted")
	}
}

func TestConfigurationErrorsNameKnownFieldsWithoutValues(t *testing.T) {
	const privateValue = "synthetic-private-value-do-not-print"
	for _, version := range []string{Version, PortableVersion, InstallationVersion} {
		fields := map[string]string{
			"version": version, "target": privateValue, "evidence_base": privateValue,
			"report_base": privateValue, "toolchain_root": privateValue, "manifest_root": privateValue,
		}
		if version == Version {
			fields["rule_pack_root"], fields["docker_base_provider"], fields["docker_scancode_provider"] = privateValue, privateValue, privateValue
		} else {
			fields["toolchain_catalog"] = privateValue
		}
		if version == InstallationVersion {
			fields["installation_state"] = privateValue
		}
		raw, _ := json.Marshal(fields)
		for field := range fields {
			t.Run(version+"/"+field, func(t *testing.T) {
				for _, value := range []any{nil, "", 123, privateValue + "\n"} {
					var bad map[string]any
					json.Unmarshal(raw, &bad)
					if value == nil {
						delete(bad, field)
					} else {
						bad[field] = value
					}
					input, _ := json.Marshal(bad)
					_, err := Decode(input)
					if err == nil || !strings.Contains(err.Error(), `"`+field+`"`) || strings.Contains(err.Error(), privateValue) {
						t.Fatalf("field=%s: expected actionable value-free rejection, got %v", field, err)
					}
				}
			})
		}
		fields[privateValue] = "unknown"
		raw, _ = json.Marshal(fields)
		if _, err := Decode(raw); err == nil || strings.Contains(err.Error(), privateValue) {
			t.Fatalf("unknown key must not be reflected: %v", err)
		}
	}
}

func installationFixture(t *testing.T) (Config, string) {
	t.Helper()
	c, file := fixture(t)
	c.Version = InstallationVersion
	c.InstallationState = filepath.Join(filepath.Dir(c.Target), "installation")
	c.ToolchainCatalog = filepath.Join(filepath.Dir(file), "catalog.json")
	if err := MakePrivateDirectory(c.InstallationState); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ToolchainCatalog, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	return c, file
}

func TestInstallationConfigRequiresExplicitVersionAndState(t *testing.T) {
	c, _ := installationFixture(t)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil || decoded != c || !decoded.UsesCatalog() || decoded.RequireExecutionVersion() != nil {
		t.Fatalf("v3 configuration rejected: %#v %v", decoded, err)
	}
	for _, version := range []string{Version, PortableVersion} {
		old := c
		old.Version = version
		if version == Version {
			old.ToolchainCatalog = ""
		}
		raw, _ := json.Marshal(old)
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "installation_state") {
			t.Fatalf("legacy version accepted installation-state authority: %v", err)
		}
		old.InstallationState = ""
		raw, _ = json.Marshal(old)
		decoded, err := Decode(raw)
		if err != nil || decoded.RequireExecutionVersion() == nil {
			t.Fatalf("historical read/execution boundary lost: %v", err)
		}
	}
	c.InstallationState = ""
	raw, _ = json.Marshal(c)
	if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "installation_state") {
		t.Fatalf("v3 without state accepted: %v", err)
	}
}

func TestInstallationStateCannotOverlapTargetInputsOrOutputs(t *testing.T) {
	c, file := installationFixture(t)
	if err := c.ValidatePaths(file); err != nil {
		t.Fatal(err)
	}
	for name, state := range map[string]string{
		"target": c.Target, "ancestor": filepath.Dir(c.Target), "configuration": filepath.Dir(file),
		"tools": c.ToolchainRoot, "rules": c.RulePackRoot, "manifests": c.ManifestRoot,
		"evidence": c.EvidenceBase, "report": c.ReportBase,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(state); os.IsNotExist(err) {
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			}
			bad := c
			bad.InstallationState = state
			if err := bad.ValidatePaths(file); err == nil {
				t.Fatal("overlapping installation state accepted")
			}
		})
	}
	for _, state := range []string{"", "relative", filepath.Join(c.InstallationState, "missing")} {
		bad := c
		bad.InstallationState = state
		if err := bad.ValidatePaths(file); err == nil {
			t.Fatalf("unavailable state accepted: %q", state)
		}
	}
	other := c
	other.InstallationState += "-other"
	if c.Digest() == other.Digest() {
		t.Fatal("installation state is not bound to configuration identity")
	}
}

func TestReadAllowsDiagnosisWithoutProbingUnavailableTarget(t *testing.T) {
	c, file := installationFixture(t)
	c.Target = filepath.Join(filepath.Dir(c.Target), "not-present")
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(file); err != nil || got != c {
		t.Fatalf("strict diagnostic read failed: %v", err)
	}
	if _, err := Load(file); err == nil {
		t.Fatal("execution path load accepted missing target")
	}
	if _, err := os.Stat(c.Target); !os.IsNotExist(err) {
		t.Fatal("diagnostic read created target")
	}
}

func TestResolveUsesUserConfigDirectoryWithoutCreatingIt(t *testing.T) {
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user config directory")
	}
	got, err := Resolve("synthetic.json")
	if err != nil || got != filepath.Join(base, "PAO", "config", "synthetic.json") {
		t.Fatalf("resolve: %q %v", got, err)
	}
	for _, name := range []string{"", "..", "../other", `..\other`, "nested/file"} {
		if _, err := Resolve(name); err == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
}
