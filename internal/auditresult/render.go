package auditresult

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
)

type PortableFinding struct {
	ID             string `json:"id"`
	Scanner        string `json:"scanner"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	PublicAdvisory string `json:"public_advisory,omitempty"`
	Evidence       string `json:"evidence_ref"`
}

type PortableReport struct {
	RunProducer              *buildinfo.Producer `json:"run_producer,omitempty"`
	RunProducerStatus        string              `json:"run_producer_status"`
	ReportProducer           *buildinfo.Producer `json:"report_producer,omitempty"`
	ReportProducerStatus     string              `json:"report_producer_status"`
	Version                  string              `json:"version"`
	ParserVersion            string              `json:"parser_version"`
	PlanDigest               string              `json:"plan_digest"`
	TargetID                 string              `json:"target_id"`
	Status                   string              `json:"status"`
	CoverageComplete         bool                `json:"coverage_complete"`
	AnalysisCoverageComplete bool                `json:"analysis_coverage_complete"`
	InventoryCoverage        InventoryCoverage   `json:"inventory_coverage"`
	Reasons                  []string            `json:"reason_codes,omitempty"`
	Inventory                int                 `json:"inventory_observations"`
	SecurityFindings         int                 `json:"security_findings"`
	LicenseObservations      int                 `json:"license_observations"`
	LicenseQuestions         int                 `json:"license_questions"`
	SBOMQualityScores        []float64           `json:"sbom_quality_scores,omitempty"`
	SBOMQualityMissing       []string            `json:"sbom_quality_missing_categories,omitempty"`
	Severities               map[string]int      `json:"security_severities"`
	Coverage                 []Coverage          `json:"coverage"`
	Findings                 []PortableFinding   `json:"findings"`
	Actions                  []string            `json:"next_actions"`
	Limitations              []string            `json:"limitations"`
}

var publicAdvisory = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,12}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})$`)

// Portable is a whitelist projection. Neither general-purpose regex redaction nor
// Markdown escaping can make arbitrary native source/message strings export-safe.
func (r Result) Portable() PortableReport {
	p := PortableReport{Version: r.Version, ParserVersion: r.ParserVersion, PlanDigest: r.PlanDigest, TargetID: r.TargetID, Status: r.Status, CoverageComplete: r.CoverageComplete, AnalysisCoverageComplete: r.AnalysisCoverageComplete, InventoryCoverage: r.InventoryCoverage, Reasons: r.Reasons, Coverage: r.Coverage, Severities: map[string]int{"UNKNOWN": 0, "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, Findings: []PortableFinding{}, SBOMQualityScores: []float64{}, SBOMQualityMissing: []string{}, Actions: []string{}, Limitations: []string{
		"Це спостереження сканерів, а не підтвердження безпеки або юридичний дозвіл.",
		"Одна проблема може бути згадана кількома сканерами; записи не видаляються і не рахуються як унікальні вразливості.",
		"Перевірено лише обраний профіль. Межі офлайн-режиму та правила сканерів залишаються чинними.",
		"Немає автоматичного вибору ліцензії, виправлення, прийняття ризику або дозволу на розповсюдження.",
		"Шляхи, назви складників і текст правил доступні лише у приватних деталях; сюди не копіюється код або вміст секретів.",
		"coverage_complete позначає завершення запуску й читання результатів. analysis_coverage_complete також враховує відомі межі входів/баз і достатність переліку для виявлених екосистем.",
		"Достатність переліку для виявлених екосистем не доводить обліку всіх версій, транзитивних, build- або runtime-залежностей; оцінка sbomqs цього не змінює.",
	}}
	p.RunProducer, p.RunProducerStatus = r.RunProducer, r.RunProducerStatus
	p.ReportProducer, p.ReportProducerStatus = r.ReportProducer, r.ReportProducerStatus
	for _, quality := range r.SBOMQuality {
		p.SBOMQualityScores = append(p.SBOMQualityScores, quality.Score)
		p.SBOMQualityMissing = append(p.SBOMQualityMissing, quality.MissingCategories()...)
	}
	p.SBOMQualityMissing = unique(p.SBOMQualityMissing)
	for _, o := range r.Observations {
		switch o.Native.Category {
		case "inventory":
			p.Inventory++
		case "license":
			p.LicenseObservations++
		}
	}
	for _, f := range r.Findings {
		if f.Category == "license" {
			p.LicenseQuestions++
		} else {
			p.SecurityFindings++
			p.Severities[f.Severity]++
		}
		x := PortableFinding{ID: f.FindingID, Scanner: f.ScannerID, Category: f.Category, Severity: f.Severity, Evidence: f.RawResultRef}
		if f.Category == "vulnerability" && publicAdvisory.MatchString(f.RuleID) {
			x.PublicAdvisory = f.RuleID
		}
		p.Findings = append(p.Findings, x)
	}
	if !p.CoverageComplete {
		p.Actions = append(p.Actions, "Спочатку з’ясуйте причини незавершених перевірок у таблиці нижче. Не вважайте їх відсутністю проблем.")
	}
	if !p.AnalysisCoverageComplete {
		p.Actions = append(p.Actions, "Перегляньте прогалини інвентаризації та підтримки входів/екосистем. Успішний запуск інструментів сам по собі не підтверджує повного аналізу залежностей.")
	}
	if p.Severities["CRITICAL"]+p.Severities["HIGH"] > 0 {
		p.Actions = append(p.Actions, "Насамперед перегляньте знахідки HIGH/CRITICAL. Зіставте їх із приватними деталями; запропоновані сканером версії ще потребують перевірки.")
	}
	if p.Severities["UNKNOWN"] > 0 {
		p.Actions = append(p.Actions, "Для UNKNOWN потрібно визначити серйозність вручну: сканер не надав придатної оцінки, PAO її не вигадує.")
	}
	if p.LicenseQuestions > 0 {
		p.Actions = append(p.Actions, "Перегляньте ліцензійні питання: відсутні відомості, неоднозначні умови та зауваження REUSE. PAO не обирає ліцензію за вас.")
	}
	if len(p.SBOMQualityScores) > 0 {
		p.Actions = append(p.Actions, "Перегляньте показник якості SBOM лише як довідковий сигнал. Він не є рішенням про безпеку, ліцензію або реліз.")
	}
	if p.SecurityFindings > 0 {
		p.Actions = append(p.Actions, "Перевірте решту знахідок за їхніми ID у приватному result.private.json або findings.private.jsonl. Не передавайте ці файли назовні без окремого рішення.")
	}
	p.Actions = append(p.Actions, "Зафіксуйте власний висновок після перегляду. Цей звіт нічого автоматично не схвалює і не змінює проєкт.")
	return p
}

type Files struct {
	Summary       []byte
	PortableJSON  []byte
	PrivateJSON   []byte
	FindingsJSONL []byte
}

func (r Result) Files() (Files, error) {
	var files Files
	var err error
	files.PrivateJSON, err = json.MarshalIndent(r, "", "  ")
	if err != nil {
		return files, err
	}
	if len(files.PrivateJSON) > maxRawBytes {
		return Files{}, errors.New("private result exceeds output limit")
	}
	p := r.Portable()
	files.PortableJSON, err = json.MarshalIndent(p, "", "  ")
	if err != nil {
		return Files{}, err
	}
	var findings bytes.Buffer
	for _, f := range r.Findings {
		data, err := normalize.CanonicalJSON(f)
		if err != nil {
			return Files{}, err
		}
		findings.Write(data)
		findings.WriteByte('\n')
	}
	files.FindingsJSONL = findings.Bytes()
	files.Summary = markdown(p)
	return files, nil
}

func categoryLabel(s string) string {
	switch s {
	case "vulnerability":
		return "Вразливість складника"
	case "secret":
		return "Можливий секрет"
	case "sast":
		return "Зауваження до коду"
	case "configuration":
		return "Налаштування автоматизації"
	case "license":
		return "Ліцензійне питання"
	case "inventory":
		return "Складник"
	}
	return "Спостереження"
}

func markdown(p PortableReport) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# PAO — зведений звіт\n\nСтан: **%s**.\n\n", p.Status)
	if p.CoverageComplete {
		b.WriteString("Запуски запланованих перевірок та читання результатів завершені (coverage_complete). Потрібен ваш перегляд; це не висновок «усе безпечно».\n\n")
	} else {
		b.WriteString("**Перевірка неповна.** Частина результатів відсутня, недоступна або не підтверджена. Наявні знахідки збережено; нуль знахідок не означає відсутність проблем.\n\n")
	}
	if !p.AnalysisCoverageComplete {
		b.WriteString("**Покриття аналізу неповне.** Відомі прогалини підтримки або інвентаризації наведено нижче; завершений запуск не закриває їх.\n\n")
	}
	fmt.Fprintf(&b, "Складників у переліку: **%d**. Знахідок безпеки: **%d**. Ліцензійних питань: **%d** (ліцензійних спостережень: %d).\n\n", p.Inventory, p.SecurityFindings, p.LicenseQuestions, p.LicenseObservations)
	if len(p.SBOMQualityScores) > 0 {
		fmt.Fprintf(&b, "Довідковий показник якості SBOM: **%.2f/10**. Він не означає схвалення безпеки, ліцензій або релізу.\n\n", p.SBOMQualityScores[0])
		if len(p.SBOMQualityMissing) > 0 {
			fmt.Fprintf(&b, "Для ручного перегляду бракує категорій даних: **%s**. Назви компонентів і шляхи не виводяться у портативний звіт.\n\n", strings.Join(p.SBOMQualityMissing, ", "))
		}
	}
	b.WriteString("Кількості позначають записи сканерів, а не унікальні підтверджені проблеми.\n\n## Достатність інвентаризації\n\n")
	fmt.Fprintf(&b, "Стан: **%s**. Очікувані екосистеми за назвами файлів: **%s**. Екосистеми у підтвердженому Syft: **%s**.\n\n", p.InventoryCoverage.Status, ecosystemList(p.InventoryCoverage.ExpectedEcosystems), ecosystemList(p.InventoryCoverage.ObservedEcosystems))
	if len(p.InventoryCoverage.Gaps) > 0 {
		b.WriteString("| Екосистема | Формат / scope hint | Прогалина |\n|---|---|---|\n")
		for _, gap := range p.InventoryCoverage.Gaps {
			fmt.Fprintf(&b, "| %s | %s / %s | %s |\n", gap.Ecosystem, gap.Format, gap.Scope, reasonLabel(gap.Reason))
		}
		b.WriteByte('\n')
	}
	b.WriteString("Назви файлів визначають очікування, а не повний граф залежностей. Build/runtime scope зафіксовано лише як підказку; PyPI-пакети не підтверджуються записами GitHub Actions.\n\n## Що робити далі\n\n")
	for i, action := range p.Actions {
		fmt.Fprintf(&b, "%d. %s\n", i+1, action)
	}
	b.WriteString("\n## Серйозність знахідок безпеки\n\n| Рівень | Кількість |\n|---|---:|\n")
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"} {
		fmt.Fprintf(&b, "| %s | %d |\n", s, p.Severities[s])
	}
	b.WriteString("\nUNKNOWN — оцінка невідома. Ліцензійні питання рахуються окремо, без вигаданої оцінки небезпеки.\n\n## Які перевірки виконані\n\n| Інструмент | Вхід / підтримка | Запуск | Читання результату | Причина / обмеження |\n|---|---|---|---|---|\n")
	for _, c := range p.Coverage {
		reasons := make([]string, 0, len(c.Reasons))
		if runner.KnownDiagnosticCode(c.DiagnosticCode) && c.DiagnosticCode != "COMPLETED" {
			reasons = append(reasons, runner.DiagnosticMessage(c.DiagnosticCode))
		}
		if c.DiagnosticsAvailable && !c.Complete {
			reasons = append(reasons, "Подробиці — приватний розділ diagnostics у run-record.json")
		}
		for _, code := range c.Reasons {
			reasons = append(reasons, reasonLabel(code))
		}
		for _, code := range c.SupportReasons {
			reasons = append(reasons, reasonLabel(code))
		}
		for _, limitation := range c.Limitations {
			reasons = append(reasons, limitation)
		}
		if len(reasons) == 0 && !c.Complete {
			reasons = append(reasons, "Потрібен перегляд приватного запису запуску")
		}
		fmt.Fprintf(&b, "| %s | %s / %s | %s | %s | %s |\n", c.Scanner, c.Applicability, c.SupportStatus, c.ExecutionStatus, c.ParsingStatus, strings.Join(unique(reasons), "; "))
	}
	if len(p.Reasons) > 0 {
		b.WriteString("\nЗагальні обмеження:\n\n")
		for _, code := range p.Reasons {
			fmt.Fprintf(&b, "- %s\n", reasonLabel(code))
		}
	}
	b.WriteString("\nPARSED — формат прочитано, а не схвалено. NOT_APPLICABLE — відповідного входу немає; це не виконана перевірка. UNSUPPORTED — вхід є, але поточний формат, екосистема або погоджена база не підтримують його. DECLARED — виконані умови manifest, без обіцянки повного охоплення всіх компонентів. PARTIAL/UNAVAILABLE/FAILED — результат не можна вважати повним.\n\n## Знахідки для перегляду\n\n")
	if len(p.Findings) == 0 {
		b.WriteString("У прочитаній частині результатів знахідки не зареєстровані. Врахуйте повноту перевірки вище.\n")
	} else {
		b.WriteString("| ID | Тип | Інструмент | Рівень | Публічний номер |\n|---|---|---|---|---|\n")
		for i, f := range p.Findings {
			if i >= 200 {
				fmt.Fprintf(&b, "\nПоказано 200 із %d записів. Повний перелік — у report.json; жоден запис не видалено.\n", len(p.Findings))
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.ID, categoryLabel(f.Category), f.Scanner, f.Severity, f.PublicAdvisory)
		}
	}
	b.WriteString("\n## Докази та межі висновку\n\n")
	fmt.Fprintf(&b, "План: `%s`  \nВідбиток проєкту: `%s`  \nВерсія обробника: `%s`\n\n", p.PlanDigest, p.TargetID, p.ParserVersion)
	for _, c := range p.Coverage {
		for _, ref := range c.Evidence {
			fmt.Fprintf(&b, "- %s: `%s`\n", c.Scanner, ref)
		}
	}
	b.WriteByte('\n')
	for _, s := range p.Limitations {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	return []byte(b.String())
}

func reasonLabel(code string) string {
	labels := map[string]string{
		"CAPTURE_TRUNCATED":      "Вивід перевищив ліміт; збережено лише початок, потрібен перегляд",
		"SKIPPED_NOT_APPLICABLE": "Відповідних файлів у плані немає", "TOOL_MISSING": "Інструмент відсутній", "TOOL_UNVERIFIED": "Інструмент не перевірений",
		"DB_MISSING": "База перевірки відсутня", "DB_STALE": "База застаріла", "STATE_MISSING": "Підготовлене середовище відсутнє", "STATE_STALE": "Підготовлене середовище застаріло",
		"RUNTIME_MISSING": "Середовище запуску відсутнє", "RUNTIME_STALE": "Строк підтвердження середовища минув", "RULE_PACK_MISSING": "Правила відсутні", "RULE_PACK_STALE": "Правила застарілі",
		"LICENSE_DATA_MISSING": "Ліцензійні дані відсутні", "LICENSE_DATA_STALE": "Ліцензійні дані застарілі", "ISOLATION_MISMATCH": "Не забезпечена необхідна ізоляція", "TIMED_OUT": "Час перевірки вичерпано",
		"MALFORMED_OUTPUT": "Пошкоджений результат", "MISSING_RESULT_FIELD": "Бракує обов’язкового поля результату", "INVALID_RESULT_FIELD": "Неправильний тип поля результату", "INVALID_ITEM": "Неповний або неправильний запис",
		"EVIDENCE_INTEGRITY_FAILURE": "Цілісність або походження доказу не підтверджені", "SCANNER_REPORTED_INCOMPLETE": "Сканер повідомив про помилки", "SCANNER_OMITTED_ITEMS": "Сканер пропустив частину матеріалів",
		"RESULT_LIMIT": "Досягнуто захисного ліміту; решта залишається у первинному доказі", "MISSING_OR_DUPLICATE_EXECUTION": "Запис запуску відсутній або дублюється", "MISSING_OR_AMBIGUOUS_RAW_RESULT": "Немає одного однозначного первинного результату",
		"UNSUPPORTED_MEDIA_TYPE": "Непідтримуваний тип результату", "UNKNOWN_TOOL_IDENTITY": "Не підтверджена версія інструмента", "UNSUPPORTED_SCHEMA_VERSION": "Непідтримувана версія формату", "MISSING_SCHEMA_VERSION": "Версія формату відсутня",
		"UNSUPPORTED_NATIVE_SCHEMA": "Нативна схема сканера не входить до перевіреного контракту",
		"UNSUPPORTED_RESULT_KIND":   "Частина типів результатів не підтримується", "MISSING_LOCATION": "Місце знахідки не визначено", "INVALID_LOCATION": "Неправильні координати знахідки", "INVALID_LICENSE_OBSERVATION": "Неправильний ліцензійний запис",
		"CONTRADICTORY_RESULT": "Поля результату суперечать одне одному", "MISSING_COMPLIANCE_DETAILS": "Бракує пояснення невідповідності REUSE", "RUN_INCOMPLETE": "Запуск завершився з помилкою", "INVALID_RUN_RECORD": "Запис запуску або незмінність проєкту не підтверджені",
		"INVALID_EXECUTION_LINEAGE": "Результат не відповідає підтвердженому плану", "INVALID_COVERAGE_REASON": "Причина стану перевірки не розпізнана", "UNCONFIRMED_SKIP": "Пропуск не підтверджений планом", "INVALID_CANONICAL_FINDING": "Не вдалося сформувати повний запис знахідки",
		"UNEXPECTED_EXECUTION": "Є непередбачений планом запуск", "INVALID_PLAN": "План не підтверджений", "INVALID_PLAN_NODE": "Неправильний перелік інструментів",
		"INVALID_SBOM_LINEAGE": "Походження CycloneDX SBOM не підтверджене", "SBOMQS_OUTPUT_INVALID": "Показник якості SBOM має непідтримуваний або пошкоджений формат",
		"SBOM_QUALITY_INCOMPLETE":             "Оцінка SBOM недоступна через неповний або непідтверджений запис перевірки",
		"DB_ECOSYSTEM_UNSUPPORTED":            "Погоджена база не покриває виявлену екосистему",
		"ECOSYSTEM_UNSUPPORTED":               "Виявлена екосистема не підтримується інструментом",
		"UNSUPPORTED_INPUT_FORMAT":            "Формат наявного входу не підтриманий або не підтверджений; розширення .lock не визначає його формат",
		"UNRECOGNIZED_SUPPORT_REASON":         "Причина обмеження підтримки не розпізнана",
		"UNRECOGNIZED_INVENTORY_EXPECTATION":  "Очікування інвентаризації має невідомий формат",
		"INVENTORY_EXPECTATIONS_NOT_RECORDED": "Старий план не містить очікувань інвентаризації",
		"INVENTORY_EVIDENCE_UNAVAILABLE":      "Підтверджена інвентаризація Syft відсутня",
		"EXPECTED_ECOSYSTEM_NOT_OBSERVED":     "Очікувана екосистема відсутня в Syft; порожній перелік залежностей не підтверджений",
		"INVENTORY_VERSION_MISSING":           "Для частини складників виявленої екосистеми не вказано версію",
		"INVENTORY_ECOSYSTEM_AMBIGUOUS":       "Тип компонента й package URL в Syft вказують на різні екосистеми",
		"SBOM_EXPORT_INVENTORY_MISMATCH":      "CycloneDX для перевірки залежностей не відповідає переліку в native Syft",
	}
	if s, ok := labels[code]; ok {
		return s + " (" + code + ")"
	}
	return "Невідома причина; потрібен ручний перегляд"
}

func ecosystemList(values []string) string {
	if len(values) == 0 {
		return "не виявлено"
	}
	return strings.Join(values, ", ")
}
