// Package doctor inspects an installation without creating state, starting a
// container, scanning the target, or contacting an Internet service.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/localaudit"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/sdk/adapter"
)

const Version = "pao.dev/doctor/v1"

type Check struct {
	ID            string   `json:"id"`
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	NextAction    string   `json:"next_action,omitempty"`
	PendingRunIDs []string `json:"pending_run_ids,omitempty"`
}

// Result describes profile prerequisites, not target applicability or a verdict.
type Result struct {
	APIVersion      string              `json:"api_version"`
	Status          string              `json:"status"`
	Profile         string              `json:"profile"`
	Scope           string              `json:"scope"`
	CheckedAt       time.Time           `json:"checked_at"`
	Producer        *buildinfo.Producer `json:"producer,omitempty"`
	ProducerStatus  string              `json:"producer_status"`
	TargetInspected bool                `json:"target_inspected"`
	ScannerStarted  bool                `json:"scanner_started"`
	NetworkAccess   bool                `json:"network_access"`
	IsolationTested bool                `json:"isolation_tested"`
	Checks          []Check             `json:"checks"`
}

type dependencies struct {
	now         func() time.Time
	producer    func() (buildinfo.Producer, error)
	runtime     func(context.Context, runner.DockerProviderConfig, string) (runner.SandboxProperties, error)
	pendingRuns func(context.Context, string) ([]string, error)
	privatePath func(string, bool) error
	platform    func() error
	supervisor  string
	superHash   string
}

func defaults() dependencies {
	executable, _ := os.Executable()
	return dependencies{
		now: time.Now, producer: buildinfo.Current, runtime: runner.CheckPreparedRuntime,
		pendingRuns: pendingRunIDs, privatePath: installation.ValidatePrivatePath,
		platform:   supportedHost,
		supervisor: filepath.Join(filepath.Dir(executable), "pao-sandbox-linux-amd64"), superHash: buildinfo.SandboxSHA256,
	}
}

func Command(ctx context.Context, args []string, output, errout io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(errout)
	config := fs.String("config", "", "private configuration path")
	profile := fs.String("profile", "mvp", "profile whose prerequisites are checked")
	asJSON := fs.Bool("json", false, "write the versioned readiness result as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if fs.NArg() != 0 || *config == "" {
		fmt.Fprintln(errout, "PAO: doctor --config FILE [--profile mvp] [--json]")
		return 3
	}
	if _, err := localaudit.ProfileTools(*profile); err != nil {
		fmt.Fprintln(errout, "PAO: невідомий профіль doctor.")
		return 3
	}
	path, err := auditconfig.Resolve(*config)
	if err != nil {
		fmt.Fprintln(errout, "PAO: потрібен абсолютний шлях конфігурації або її приватне коротке ім'я.")
		return 3
	}
	result := inspect(ctx, path, *profile, defaults())
	if *asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(errout, "PAO: не вдалося записати результат doctor.")
			return 3
		}
	} else {
		fmt.Fprintf(output, "%s: готовність середовища для %s; ціль і сканери не запускалися.\n", result.Status, result.Profile)
		for _, check := range result.Checks {
			fmt.Fprintf(output, "[%s] %s: %s\n", check.Status, check.ID, check.Reason)
			if len(check.PendingRunIDs) != 0 {
				fmt.Fprintf(output, "  Ідентифікатори незавершених запусків: %s\n", strings.Join(check.PendingRunIDs, ", "))
			}
			if check.NextAction != "" {
				fmt.Fprintf(output, "  %s\n", check.NextAction)
			}
		}
		fmt.Fprintln(output, "READY не є висновком безпеки. Ізоляцію перевіряє окремий pao setup --verify.")
	}
	if result.Status != "READY" {
		return 5
	}
	return 0
}

func inspect(ctx context.Context, configPath, profile string, d dependencies) (result Result) {
	now := d.now().UTC()
	result = Result{APIVersion: Version, Status: "READY", Profile: profile, Scope: "profile-prerequisites", CheckedAt: now, Checks: []Check{}}
	add := func(id string, err error, success, problem, action string) bool {
		check := Check{ID: id, Status: "READY", Reason: success}
		if err != nil {
			check.Status, check.Reason, check.NextAction = "SETUP_REQUIRED", problem, action
			result.Status = "SETUP_REQUIRED"
		}
		result.Checks = append(result.Checks, check)
		return err == nil
	}
	defer func() {
		sort.SliceStable(result.Checks, func(i, j int) bool { return result.Checks[i].ID < result.Checks[j].ID })
	}()
	producer, err := d.producer()
	result.ProducerStatus = "UNAVAILABLE"
	if err == nil {
		err = producer.Validate()
	}
	if err == nil {
		result.Producer, result.ProducerStatus = &producer, "RECORDED"
	}
	add("package.identity", err, "Ідентичність PAO прочитано.", "Ідентичність PAO недоступна.", "Перевірте пакет і його контрольні суми.")
	var platformErr error
	if runtime.GOARCH != "amd64" || (runtime.GOOS != "windows" && runtime.GOOS != "linux") {
		platformErr = errors.New("unsupported platform")
	} else {
		platformErr = d.platform()
	}
	add("host.platform", platformErr, "Хост відповідає підтриманій ОС та архітектурі.", "Архітектура або ОС не підтримана.", "Використайте Windows 11 x64 або Ubuntu 24.04 x64.")
	add("package.supervisor", verifyFile(ctx, d.supervisor, d.superHash, 128<<20), "Помічник PAO відповідає цій збірці.", "Помічник PAO відсутній або не відповідає збірці.", "Розпакуйте повний перевірений пакет у нову папку.")
	raw, err := readBounded(ctx, configPath, auditconfig.MaxBytes)
	if !add("config.read", err, "Конфігурацію прочитано.", "Конфігурація недоступна, небезпечна або завелика.", "Виконайте pao setup у новому приватному каталозі.") {
		return
	}
	c, err := auditconfig.Decode(raw)
	if !add("config.format", err, "Формат конфігурації коректний.", "Конфігурація містить неприпустимі або відсутні поля.", "Створіть або імпортуйте конфігурацію через pao setup.") {
		return
	}
	if c.Version != auditconfig.InstallationVersion {
		add("config.migration", errors.New("legacy"), "", "Виконання потребує конфігурації v3 зі спільним станом установки.", "Виконайте pao setup --root NEW --import-config OLD --apply; оригінал зберігається.")
	}
	add("config.paths", c.ValidatePaths(configPath), "Шляхи конфігурації допустимі.", "Один або більше шляхів недоступні, перекриваються або перенаправлені.", "Виправте перелічені перевірки шляхів або повторіть setup.")
	// A malformed configuration must not redirect prerequisite inspection into
	// the target. We inspect its pathname, never its contents or Git metadata.
	inputs := []struct {
		id, path string
		private  bool
	}{
		{"config.directory", filepath.Dir(configPath), true}, {"installation.state", c.InstallationState, true},
		{"evidence.root", c.EvidenceBase, true}, {"reports.root", c.ReportBase, true},
		{"toolchain.root", c.ToolchainRoot, true}, {"rules.root", c.RulePackRoot, false}, {"manifests.root", c.ManifestRoot, false},
	}
	unsafeInputs := false
	for _, p := range inputs {
		if p.path == "" && p.id == "rules.root" {
			continue
		}
		var pathErr error
		if p.path == "" || !filepath.IsAbs(p.path) || auditconfig.Overlap(c.Target, p.path) {
			pathErr = errors.New("unsafe root")
			unsafeInputs = true
		} else if p.private {
			pathErr = d.privatePath(p.path, true)
		} else {
			pathErr = auditconfig.CheckPath(p.path, false)
		}
		add(p.id, pathErr, "Каталог доступний із потрібними межами доступу.", "Каталог відсутній, небезпечний або має надмірні права.", "Підготуйте окремий приватний каталог через setup; не послаблюйте перевірки.")
	}
	for _, path := range []string{c.ToolchainCatalog, c.DockerBaseProvider, c.DockerScanCodeProvider} {
		if path != "" && (!filepath.IsAbs(path) || auditconfig.Overlap(c.Target, path)) {
			unsafeInputs = true
		}
	}
	if unsafeInputs {
		return
	}
	pending, stateErr := d.pendingRuns(ctx, c.InstallationState)
	if stateErr == nil && len(pending) != 0 {
		stateErr = errors.New("pending installation lifecycle")
	} else if stateErr != nil {
		// A failed inventory may contain incomplete or untrusted data. Never
		// reflect its IDs or raw error (which can contain private paths).
		pending = nil
	}
	stateReady := add("installation.journal", stateErr, "Незавершених запусків немає.", "Стан установки недоступний або є незавершений запуск.", "Перевірте pao recover --config FILE --run ID; докази не видаляйте.")
	if len(pending) != 0 {
		check := &result.Checks[len(result.Checks)-1]
		check.PendingRunIDs = pending
		check.NextAction = "Перегляньте pao recover --config FILE --run " + pending[0] + "; після відновлення повторіть doctor. Докази не видаляйте."
	}
	catalog, err := toolchain.LoadCatalog(c.ToolchainCatalog, now)
	if !add("catalog.approval", err, "Каталог має чинне погодження.", "Каталог відсутній, некоректний або погодження прострочене.", "Підготуйте актуальні ресурси й погодьте їх через setup; не пересувайте дати вручну.") {
		return
	}
	records := make([]toolchain.Record, 0, len(catalog.Tools))
	byID := map[string]toolchain.CatalogTool{}
	for _, tool := range catalog.Tools {
		byID[tool.Record.ID] = tool
		records = append(records, tool.Record)
	}
	registry, err := toolchain.New(records)
	if !add("catalog.records", err, "Записи каталогу коректні.", "Записи каталогу некоректні.", "Повторіть перевірену підготовку каталогу.") {
		return
	}
	providers := map[string]bool{}
	ids, err := localaudit.ProfileTools(profile)
	if !add("profile", err, "Профіль розпізнано.", "Профіль не підтриманий.", "Оберіть документований профіль PAO.") {
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			add("cancelled", ctx.Err(), "", "Перевірку скасовано.", "Повторіть doctor, коли середовище буде доступне.")
			return
		}
		tool, exists := byID[id]
		if !exists {
			add("tool."+id, errors.New("missing"), "", "Інструмент відсутній у погодженому каталозі.", "Підготуйте вибраний профіль через setup.")
			continue
		}
		providers[tool.Provider] = true
		manifestPath := filepath.Join(c.ManifestRoot, id, "manifest.json")
		var manifest adapter.Manifest
		manifestErr := auditconfig.CheckPath(manifestPath, false)
		if manifestErr == nil {
			manifest, manifestErr = adapter.LoadFile(manifestPath)
		}
		if manifestErr == nil && (manifest.ID != id || manifest.SourceLicense != tool.Record.SourceLicense || manifest.Redistribution != tool.Record.Redistribution || !contains(manifest.CompatibleToolVersions, tool.Record.Version)) {
			manifestErr = errors.New("manifest differs")
		}
		if manifestErr == nil {
			environment := make(map[string]string)
			for k, v := range tool.Record.DatabaseEnvironment {
				environment[k] = v
			}
			for k, v := range tool.Record.StateEnvironment {
				environment[k] = v
			}
			manifestErr = manifest.AllowsEnvironment(environment)
		}
		add("tool."+id+".contract", manifestErr, "Версія та умови інструмента відповідають адаптеру.", "Декларація або версія інструмента не відповідає адаптеру.", "Використайте рецепт із цього перевіреного пакета.")
		binary := filepath.Join(c.ToolchainRoot, filepath.FromSlash(tool.Binary))
		add("tool."+id+".binary", verifyFile(ctx, binary, "sha256:"+tool.Record.SHA256, runner.FrozenMaxFileBytes), "SHA-256 інструмента збігається.", "Інструмент недоступний або його байти змінилися.", "Повторіть setup; нові байти потребують перевірки.")
		requirement := toolchain.Requirement{ToolID: id, Capability: "readiness", RequiresRuntime: true, MaximumRuntimeAge: toolchain.MaximumPrerequisiteAge,
			RequiresDatabase: tool.Database != "", MaximumDatabaseAge: toolchain.DatabaseMaximumAge(id), RequiresState: tool.State != "", MaximumStateAge: toolchain.MaximumPrerequisiteAge,
			RequiresRulePack: tool.RulePack != "", MaximumRulePackAge: toolchain.MaximumPrerequisiteAge, RequiresLicenseData: tool.Record.LicenseDataSHA256 != "", MaximumLicenseDataAge: toolchain.MaximumPrerequisiteAge}
		coverage := registry.Preflight(requirement, now)
		var freshnessErr error
		if coverage.Status != "AVAILABLE_NOT_STARTED" {
			freshnessErr = errors.New(coverage.ReasonCode)
		}
		add("tool."+id+".freshness", freshnessErr, "Строки ресурсів чинні.", "Ресурси відсутні, прострочені або датовані майбутнім: "+coverage.ReasonCode, "Отримайте новий знімок або проведіть новий перегляд через setup.")
		stateVerified := false
		for _, resource := range []struct{ kind, root, path, digest string }{{"database", c.ToolchainRoot, tool.Database, tool.Record.DatabaseSHA256}, {"state", c.ToolchainRoot, tool.State, tool.Record.StateSHA256}, {"rules", c.RulePackRoot, tool.RulePack, tool.Record.RulePackSHA256}} {
			if resource.path == "" {
				continue
			}
			resourcePath := filepath.Join(resource.root, filepath.FromSlash(resource.path))
			verified := add("tool."+id+"."+resource.kind, verifyCapsule(ctx, resourcePath, resource.kind, "sha256:"+resource.digest, id), "Склад і хеші ресурсу перевірено.", "Склад або хеші ресурсу не відповідають каталогу.", "Повторіть підготовку цього ресурсу; аудит не оновлює його автоматично.")
			if resource.kind == "state" {
				stateVerified = verified
			}
		}
		if tool.StateEntrypoint != "" {
			entrypointErr := errors.New("prepared state was not verified")
			if stateVerified {
				stateRoot := filepath.Join(c.ToolchainRoot, filepath.FromSlash(tool.State))
				entrypointErr = verifyStateEntrypoint(ctx, stateRoot, tool.StateEntrypoint, "sha256:"+tool.Record.StateSHA256)
			}
			add("tool."+id+".entrypoint", entrypointErr, "Файл запуску присутній у перевіреному складі ресурсу.", "Файл запуску відсутній, небезпечний або не задекларований у ресурсі.", "Повторіть підготовку стану інструмента через setup.")
		}
	}
	for _, kind := range []string{"base", "scancode"} {
		if !providers[kind] {
			continue
		}
		file := c.DockerBaseProvider
		if kind == "scancode" {
			file = c.DockerScanCodeProvider
		}
		provider, err := runner.LoadDockerProviderConfig(file, now)
		if err == nil {
			for _, tool := range catalog.Tools {
				if tool.Provider == kind && provider.RuntimeImage != "sha256:"+tool.Record.RuntimeSHA256 {
					err = errors.New("runtime mismatch")
					break
				}
			}
		}
		if !add("runtime."+kind+".approval", err, "Погодження Docker CLI та runtime чинне.", "Docker CLI, runtime або його погодження змінилися чи прострочені.", "Повторіть setup та окрему синтетичну перевірку runtime.") {
			continue
		}
		if !stateReady {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err = d.runtime(probeCtx, provider, c.InstallationState)
		cancel()
		add("runtime."+kind+".availability", err, "Локальний Docker Desktop і потрібний образ доступні; контейнер не запускався.", "Локальний Docker Desktop, перевірена CLI-копія або образ недоступні.", "Запустіть підтриманий Docker Desktop; після його оновлення повторіть setup.")
	}
	return
}

// The state inventory has already been verified. Re-read only its small,
// digest-bound manifest to establish that the selected executable is a payload
// file, rather than a directory or the inventory itself. Execution independently
// freezes and verifies the capsule before it launches the entrypoint.
func verifyStateEntrypoint(ctx context.Context, root, entrypoint, stateDigest string) error {
	if !toolchain.SafeRelative(entrypoint) {
		return errors.New("unsafe prepared-state entrypoint")
	}
	raw, err := readBounded(ctx, filepath.Join(root, "pao-state-manifest.json"), runner.FrozenMaxManifestBytes)
	if err != nil {
		return err
	}
	if auditconfig.Digest(raw) != stateDigest {
		return errors.New("prepared-state manifest changed")
	}
	var manifest capsuleManifest
	if err := strictjson.Decode(raw, &manifest, int(runner.FrozenMaxManifestBytes)); err != nil {
		return err
	}
	declared := false
	for _, file := range manifest.Files {
		if file.Path == entrypoint {
			declared = true
			break
		}
	}
	if !declared {
		return errors.New("prepared-state entrypoint is not a declared payload")
	}
	path := filepath.Join(root, filepath.FromSlash(entrypoint))
	if err := auditconfig.CheckPath(path, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("prepared-state entrypoint is not a regular file")
	}
	return ctx.Err()
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// Kept explicit rather than inheriting environment variables or CLI context.
func cleanDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
