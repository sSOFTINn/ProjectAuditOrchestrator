package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/target"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

// These opt-in tests use installed, pinned upstream tools and local images.
// They never download, update databases, run target code, or inspect a real
// project. Run each named test serially with an outer timeout of at least 20m.
// PAO_ADDITIONAL_STAGE_ROOT and the child process TEMP/TMP must point inside the
// explicitly approved staging tree. Evidence remains there for inspection.
func TestAdditionalUpstreamSyftThroughHostRunner(t *testing.T)     { additionalUpstream(t, "syft") }
func TestAdditionalUpstreamGrypeThroughHostRunner(t *testing.T)    { additionalUpstream(t, "grype") }
func TestAdditionalUpstreamOSVThroughHostRunner(t *testing.T)      { additionalUpstream(t, "osv-scanner") }
func TestAdditionalUpstreamTrivyThroughHostRunner(t *testing.T)    { additionalUpstream(t, "trivy") }
func TestAdditionalUpstreamGitleaksThroughHostRunner(t *testing.T) { additionalUpstream(t, "gitleaks") }
func TestAdditionalUpstreamZizmorThroughHostRunner(t *testing.T)   { additionalUpstream(t, "zizmor") }
func TestAdditionalUpstreamREUSEThroughHostRunner(t *testing.T)    { additionalUpstream(t, "reuse") }

var additionalUpstreamPins = map[string]struct{ version, sha256 string }{
	"syft":        {"1.51.1", "abca2def61de9952fa06d3977bb1e064818facb9badfce502b450d3d6846a91f"},
	"grype":       {"0.118.0", "91705979c6ccb736b87e3250831f5e1a35f13767fd2032ffa85c55b1e6f58f90"},
	"osv-scanner": {"2.5.1", "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be"},
	"trivy":       {"0.74.0", "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791"},
	"gitleaks":    {"8.30.1", "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"},
	"zizmor":      {"1.29.0", "a3331b0a69fc0d8bf8087b0d74d5424602c5a0f2fc2770afe2e908a1295692b5"},
	"reuse":       {"6.2.0", "4feae057a2334c9a513e6933cdb9be819d8b822f3b5b435a36138bd218897d23"},
}

func additionalUpstream(t *testing.T, id string) {
	t.Helper()
	if os.Getenv("PAO_ADDITIONAL_UPSTREAM_INTEGRATION") != "1" {
		t.Skip("set PAO_ADDITIONAL_UPSTREAM_INTEGRATION=1 for installed upstream acceptance")
	}
	root := additionalExistingPath(t, "PAO_ADDITIONAL_TOOLCHAIN_ROOT", true)
	catalogPath := additionalExistingPath(t, "PAO_ADDITIONAL_TOOLCHAIN_CATALOG", false)
	stage := additionalExistingPath(t, "PAO_ADDITIONAL_STAGE_ROOT", true)
	for _, protected := range []string{repositoryPath(t), root, filepath.Dir(catalogPath)} {
		if target.IsInside(protected, stage) || target.IsInside(stage, protected) {
			t.Fatal("staging must be separate from source, installed tools and catalog")
		}
	}
	if !target.IsInside(stage, os.TempDir()) {
		t.Fatal("child process TEMP/TMP must be inside the explicitly approved staging root")
	}
	catalog, err := toolchain.LoadCatalog(catalogPath, time.Now().UTC())
	if err != nil {
		t.Fatalf("current explicit catalog approval is unavailable: %v", err)
	}
	installed := additionalCatalogTool(t, catalog, id)
	manifest := loadProductionManifest(t, id)
	pin := additionalUpstreamPins[id]
	if installed.Record.Version != pin.version || installed.Record.SHA256 != pin.sha256 || installed.Record.SourceLicense != manifest.SourceLicense || installed.Record.Redistribution != "user-installed-only" {
		t.Fatal("installed candidate record does not match the reviewed version, binary pin or license")
	}
	registry, err := toolchain.New([]toolchain.Record{installed.Record})
	if err != nil {
		t.Fatal(err)
	}
	toolPath := additionalRelativePath(t, root, installed.Binary)
	if fileDigestHex(t, toolPath) != pin.sha256 {
		t.Fatal("installed upstream binary bytes do not match their recorded pin")
	}
	caseRoot := additionalPrivateDirectory(t, stage, "upstream-"+id+"-")
	t.Logf("retained synthetic acceptance evidence: %s", caseRoot)
	targetRoot := additionalPrivateChild(t, caseRoot, "target")
	temporary := additionalPrivateChild(t, caseRoot, "output")
	store, err := artifact.Open(additionalPrivateChild(t, caseRoot, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	additionalWriteFixture(t, targetRoot, id)
	runtimeDigest := "sha256:" + installed.Record.RuntimeSHA256
	spec := ExecutionSpec{
		APIVersion: "pao.dev/execution/v1alpha1", AdapterID: id, ToolID: id,
		ToolPath: toolPath, ToolDigest: "sha256:" + pin.sha256,
		RuntimeDigest: runtimeDigest, TargetRoot: targetRoot, TemporaryDir: temporary,
		Environment: map[string]string{}, TimeoutSeconds: min(manifest.TimeoutSeconds, 900),
		MaxOutputBytes: 8 << 20, MemoryMB: 2048, Sandbox: strongSandbox(),
	}
	if installed.Database != "" {
		spec.DatabasePath = additionalRelativePath(t, root, installed.Database)
		spec.DatabaseDigest = "sha256:" + installed.Record.DatabaseSHA256
	}
	if installed.State != "" {
		spec.StatePath = additionalRelativePath(t, root, installed.State)
		spec.StateDigest = "sha256:" + installed.Record.StateSHA256
		spec.StateEntrypoint = installed.StateEntrypoint
	}
	for _, approvedEnvironment := range []map[string]string{installed.Record.DatabaseEnvironment, installed.Record.StateEnvironment} {
		for key, value := range approvedEnvironment {
			spec.Environment[key] = value
		}
	}
	if id != "zizmor" && id != "reuse" {
		spec.OutputFile, spec.OutputMediaType = id+".json", "application/json"
	}
	if id == "syft" {
		spec.OutputMediaType = "application/vnd.syft+json"
		spec.AdditionalOutputs = []DeclaredOutput{{File: "syft.cdx.json", MediaType: "application/vnd.cyclonedx+json"}}
	}
	if id == "grype" {
		// Inert, minimal CycloneDX input describes a historically vulnerable Go
		// dependency. It is captured before execution and never built or fetched.
		input, putErr := store.PutRaw("application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"golang.org/x/text","version":"v0.3.0","purl":"pkg:golang/golang.org/x/text@v0.3.0"}]}`), "synthetic-grype-input")
		if putErr != nil {
			t.Fatal(putErr)
		}
		spec.InputPath, spec.InputDigest = filepath.Join(store.Root(), filepath.FromSlash(input.Path)), input.SHA256
	}
	spec.Arguments, err = ManifestArguments(manifest, spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 19*time.Minute)
	defer cancel()
	before, err := target.SnapshotRootContext(ctx, targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	host := productionDockerHost(t, runtimeDigest)
	outcome, runErr := (HostRunner{
		Registry: registry, Host: host, Artifacts: store,
		Progress: func(stage Stage) { t.Logf("%s: %s", id, stage) },
	}).ExecuteDeclared(ctx, spec, manifest, recordDigest, recordDigest, "exec-additional-"+id, manifest.Capabilities[0])
	after, snapshotErr := target.SnapshotRootContext(ctx, targetRoot)
	additionalWriteJSON(t, filepath.Join(caseRoot, "execution.json"), struct {
		CatalogDigest  string           `json:"catalog_digest"`
		OriginalRecord toolchain.Record `json:"original_record"`
		Spec           ExecutionSpec    `json:"spec"`
		Before         target.Snapshot  `json:"target_before"`
		After          target.Snapshot  `json:"target_after"`
		Execution      ToolExecution    `json:"execution"`
	}{catalog.Digest, installed.Record, spec, before, after, outcome})
	if snapshotErr != nil || !before.Complete || !after.Complete || before.TargetID != after.TargetID {
		t.Fatalf("synthetic target changed or cannot be verified: %v", snapshotErr)
	}
	if runErr != nil || outcome.Status != Succeeded {
		t.Fatalf("upstream acceptance unavailable/failed (not PASS): status=%s diagnostic=%s reason=%s error=%v; evidence=%s", outcome.Status, outcome.DiagnosticCode, outcome.Coverage.Reason, runErr, caseRoot)
	}
	expectedArtifacts := 1
	if id == "syft" {
		expectedArtifacts = 2
	}
	if len(outcome.RawArtifacts) != expectedArtifacts {
		t.Fatal("successful upstream execution did not capture the exact declared output set")
	}
	for index, ref := range outcome.RawArtifacts {
		contents, readErr := readDeclaredOutput(store.Root(), ref.Path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		sum := sha256.Sum256(contents)
		if ref.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || ref.Size != int64(len(contents)) {
			t.Fatal("captured native output bytes no longer match their immutable evidence reference")
		}
		var raw any
		decoder := json.NewDecoder(bytes.NewReader(contents))
		decoder.UseNumber()
		if decoder.Decode(&raw) != nil || decoder.Decode(new(any)) != io.EOF {
			t.Fatal("captured upstream output is not one complete JSON value")
		}
		if id == "syft" && index == 1 {
			additionalAssertCycloneDX(t, raw)
		} else {
			additionalAssertNative(t, id, raw)
		}
	}
	additionalWriteJSON(t, filepath.Join(caseRoot, "acceptance.json"), struct {
		Tool                             string `json:"tool"`
		Version                          string `json:"version"`
		NativeContractAndPositiveControl bool   `json:"native_contract_and_positive_control"`
		TargetUnchanged                  bool   `json:"target_unchanged"`
	}{id, pin.version, true, true})
}

func additionalCatalogTool(t *testing.T, catalog toolchain.Catalog, id string) toolchain.CatalogTool {
	t.Helper()
	for _, installed := range catalog.Tools {
		if installed.Record.ID == id {
			return installed
		}
	}
	if id != "osv-scanner" {
		t.Fatal("candidate is absent from the explicitly approved current catalog")
	}
	// OSV is the existing legacy-reviewed Go-only database, not a new approval
	// or a refreshed timestamp. The current catalog intentionally omits it.
	approvedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return toolchain.CatalogTool{
		Binary: "osv-scanner/2.5.1/bin/osv-scanner_linux_amd64", Provider: "base",
		Database: "osv-scanner/2.5.1/database/2026-09-03-readable-v1",
		Record: toolchain.Record{
			ID: "osv-scanner", Version: "2.5.1", SHA256: additionalUpstreamPins["osv-scanner"].sha256,
			SourceLicense: "Apache-2.0", Redistribution: "user-installed-only",
			DatabaseSHA256: "7972609e63c4e6b3d1c5bfc61bff788e6161999bf4eea7b34dfde76171894d17", DatabaseAt: approvedAt,
			DatabaseEnvironment: map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/pao/database"},
			RuntimeSHA256:       "8ec5c4cb7273dc9cb3a17ea920623700f7fdeabc9dcb52620b569f0f7434f97f", RuntimeAt: approvedAt,
		},
	}
}

func additionalExistingPath(t *testing.T, environment string, directory bool) string {
	t.Helper()
	value := requiredEnvironment(t, environment)
	if err := auditconfig.CheckPath(value, false); err != nil {
		t.Fatalf("%s: %v", environment, err)
	}
	info, err := os.Lstat(value)
	if err != nil || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		t.Fatalf("%s has the wrong file type", environment)
	}
	return value
}

func additionalRelativePath(t *testing.T, root, relative string) string {
	t.Helper()
	if !toolchain.SafeRelative(relative) {
		t.Fatal("unsafe installed candidate path")
	}
	value := filepath.Join(root, filepath.FromSlash(relative))
	if err := auditconfig.CheckPath(value, false); err != nil {
		t.Fatal(err)
	}
	return value
}

func additionalPrivateDirectory(t *testing.T, parent, prefix string) string {
	t.Helper()
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	return additionalPrivateChild(t, parent, prefix+hex.EncodeToString(suffix[:]))
}

func additionalPrivateChild(t *testing.T, parent, name string) string {
	t.Helper()
	value := filepath.Join(parent, name)
	if err := auditconfig.MakePrivateDirectory(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func additionalWriteFixture(t *testing.T, root, id string) {
	t.Helper()
	name, content := "go.mod", "module pao-synthetic-upstream-control\n\ngo 1.20\n\nrequire golang.org/x/text v0.3.0\n"
	switch id {
	case "gitleaks":
		// Deliberately fake, never issued by GitHub. Constructing its prefix
		// separately also avoids making the harness itself a secret fixture.
		// The previous alphabet sequence matches an upstream global stopword;
		// this public marker's digest supplies a deterministic inert control.
		marker := sha256.Sum256([]byte("pao-inert-synthetic-gitleaks-acceptance"))
		name, content = "synthetic-secret.txt", "test_token="+"ghp_"+hex.EncodeToString(marker[:])[:36]+"\n"
	case "zizmor":
		dir := additionalPrivateChild(t, root, ".github")
		additionalPrivateChild(t, dir, "workflows")
		name = ".github/workflows/synthetic.yml"
		content = "name: synthetic-inert-control\non: pull_request_target\npermissions: write-all\njobs:\n  fixture:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo '${{ github.event.pull_request.title }}'\n"
	case "reuse":
		name, content = "missing-license.txt", "Inert synthetic text deliberately missing SPDX headers.\n"
	}
	file, err := os.OpenFile(filepath.Join(root, filepath.FromSlash(name)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func additionalWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func additionalObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("native result requires an object")
	}
	return object
}

func additionalArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatal("native result requires an array")
	}
	return array
}

func additionalText(value any) string { text, _ := value.(string); return text }
func additionalControlVersion(value any) bool {
	return strings.TrimPrefix(additionalText(value), "v") == "0.3.0"
}

func additionalAssertCycloneDX(t *testing.T, value any) {
	t.Helper()
	m := additionalObject(t, value)
	if additionalText(m["bomFormat"]) != "CycloneDX" || additionalText(m["specVersion"]) != "1.7" {
		t.Fatal("Syft pinned CycloneDX output contract differs from expected 1.7")
	}
	for _, component := range additionalArray(t, m["components"]) {
		item := additionalObject(t, component)
		if additionalText(item["name"]) == "golang.org/x/text" && additionalControlVersion(item["version"]) {
			return
		}
	}
	t.Fatal("CycloneDX output omitted the exact synthetic Go dependency")
}

func additionalAssertNative(t *testing.T, id string, value any) {
	t.Helper()
	if id == "gitleaks" || id == "zizmor" {
		items := additionalArray(t, value)
		for _, item := range items {
			m := additionalObject(t, item)
			if id == "gitleaks" {
				if additionalText(m["RuleID"]) == "github-pat" && strings.HasSuffix(additionalText(m["File"]), "synthetic-secret.txt") && m["StartLine"] == json.Number("1") && additionalText(m["Secret"]) == "REDACTED" {
					return
				}
			} else if additionalText(m["ident"]) == "template-injection" && len(additionalArray(t, m["locations"])) > 0 && additionalText(additionalObject(t, m["determinations"])["severity"]) != "" {
				return
			}
		}
		t.Fatal("native array omitted the exact synthetic positive control")
	}
	m := additionalObject(t, value)
	switch id {
	case "syft":
		if additionalText(additionalObject(t, m["schema"])["version"]) != "16.1.10" || additionalText(additionalObject(t, m["descriptor"])["version"]) != additionalUpstreamPins[id].version {
			t.Fatal("Syft native schema or producer version does not match the pinned contract")
		}
		for _, item := range additionalArray(t, m["artifacts"]) {
			a := additionalObject(t, item)
			if additionalText(a["name"]) == "golang.org/x/text" && additionalControlVersion(a["version"]) {
				return
			}
		}
	case "grype":
		if additionalText(additionalObject(t, m["descriptor"])["version"]) != additionalUpstreamPins[id].version {
			t.Fatal("Grype producer version does not match the pinned contract")
		}
		for _, item := range additionalArray(t, m["matches"]) {
			x := additionalObject(t, item)
			a, v := additionalObject(t, x["artifact"]), additionalObject(t, x["vulnerability"])
			if additionalText(a["name"]) == "golang.org/x/text" && additionalControlVersion(a["version"]) && additionalText(v["id"]) != "" {
				return
			}
		}
	case "osv-scanner":
		for _, result := range additionalArray(t, m["results"]) {
			row := additionalObject(t, result)
			if !strings.HasSuffix(additionalText(additionalObject(t, row["source"])["path"]), "go.mod") {
				continue
			}
			for _, item := range additionalArray(t, row["packages"]) {
				x := additionalObject(t, item)
				a := additionalObject(t, x["package"])
				if additionalText(a["name"]) != "golang.org/x/text" || !additionalControlVersion(a["version"]) {
					continue
				}
				for _, vulnerability := range additionalArray(t, x["vulnerabilities"]) {
					if additionalText(additionalObject(t, vulnerability)["id"]) == "GO-2021-0113" {
						return
					}
				}
			}
		}
	case "trivy":
		if m["SchemaVersion"] != json.Number("2") {
			t.Fatal("Trivy native schema must be version 2")
		}
		for _, result := range additionalArray(t, m["Results"]) {
			x := additionalObject(t, result)
			if additionalText(x["Class"]) != "lang-pkgs" || !strings.HasSuffix(additionalText(x["Target"]), "go.mod") {
				continue
			}
			for _, vulnerability := range additionalArray(t, x["Vulnerabilities"]) {
				v := additionalObject(t, vulnerability)
				if additionalText(v["PkgName"]) == "golang.org/x/text" && additionalControlVersion(v["InstalledVersion"]) && additionalText(v["VulnerabilityID"]) != "" {
					return
				}
			}
		}
	case "reuse":
		summary := additionalObject(t, m["summary"])
		if additionalText(m["lint_version"]) != "1.0" || summary["compliant"] != false || summary["files_total"] != json.Number("1") || len(additionalArray(t, m["files"])) != 1 {
			t.Fatal("REUSE native lint 1.0 contract or noncompliant fixture summary differs")
		}
		found := false
		for key, names := range additionalObject(t, m["non_compliant"]) {
			if key == "read_errors" && len(additionalArray(t, names)) > 0 {
				t.Fatal("REUSE reported fixture read errors")
			}
			for _, name := range additionalArray(t, names) {
				if strings.HasSuffix(additionalText(name), "missing-license.txt") {
					found = true
				}
			}
		}
		if found {
			return
		}
	}
	t.Fatal("native upstream output omitted the exact synthetic dependency or compliance positive control")
}
