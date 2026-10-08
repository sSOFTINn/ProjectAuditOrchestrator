package runner

import "github.com/sSOFTINn/ProjectAuditOrchestrator/internal/artifact"

const MaxDiagnosticBytes = 256 << 10

type Stage string

const (
	StageValidate  Stage = "validate"
	StageState     Stage = "state"
	StageDatabase  Stage = "database"
	StageRules     Stage = "rules"
	StageTool      Stage = "tool"
	StageApproval  Stage = "approval"
	StageIsolation Stage = "isolation"
	StageLaunch    Stage = "launch"
	StagePersist   Stage = "persist"
)

func StageMessage(s Stage) string {
	switch s {
	case StageValidate:
		return "перевіряємо умови запуску"
	case StageState:
		return "перевіряємо цілісність підготовленого середовища"
	case StageDatabase:
		return "перевіряємо цілісність локальної бази"
	case StageRules:
		return "перевіряємо правила"
	case StageTool:
		return "перевіряємо інструмент"
	case StageApproval:
		return "перевіряємо чинність погоджень"
	case StageIsolation:
		return "перевіряємо ізоляцію Docker"
	case StageLaunch:
		return "виконуємо сканування"
	case StagePersist:
		return "зберігаємо результат і приватну діагностику"
	default:
		return "виконуємо перевірку"
	}
}

// Codes are selected by trusted control flow, never by matching scanner prose.
var diagnosticMessages = map[string]string{
	"DECLARATION_REJECTED":          "Умови запуску не підтверджені. Перевірте налаштування PAO.",
	"STATE_CHECK_FAILED":            "Підготовлене середовище не пройшло перевірку. Перевірте його наявність і цілісність.",
	"DATABASE_CHECK_FAILED":         "Локальна база не пройшла перевірку. Перевірте її наявність і цілісність.",
	"RULES_CHECK_FAILED":            "Правила перевірки недоступні або пошкоджені. Перевірте підготовлений набір правил.",
	"TOOL_CHECK_FAILED":             "Інструмент відсутній або його контрольна сума не збігається. Перевірте встановлену копію.",
	"APPROVAL_CHECK_FAILED":         "Погодження або закріплені налаштування не підтверджені. Потрібен перегляд власника.",
	"ISOLATION_CHECK_FAILED":        "Не вдалося підтвердити захист Docker. Перевірте, чи він працює; не вимикайте захист.",
	"SCANNER_FAILED":                "Сканер завершився зі збоєм. Перегляньте приватну діагностику; це не відсутність проблем.",
	"HOST_START_FAILED":             "Не вдалося запустити сканер у Docker. Перевірте Docker та приватний запис запуску.",
	"OUTPUT_MISSING_OR_UNSAFE":      "Сканер не надав придатний файл результату. Перегляньте приватну діагностику.",
	"OUTPUT_LIMIT":                  "Досягнуто ліміту захоплення виводу. Збережено початок; результат неповний.",
	"DIAGNOSTIC_STORAGE_FAILED":     "Не вдалося зберегти приватну діагностику. Перевірте вільне місце і доступ до папки доказів.",
	"EVIDENCE_STORE_FAILED":         "Не вдалося зберегти первинний результат. Перевірте вільне місце і доступ до папки доказів.",
	"INPUT_CLEANUP_FAILED":          "Не вдалося прибрати тимчасові приватні копії. Перегляньте запис запуску перед ручним очищенням.",
	"CONTAINER_CLEANUP_UNCONFIRMED": "Зупинку контейнера не підтверджено. Приватні копії збережено; потрібна окрема перевірка власника перед очищенням.",
	"TIMED_OUT":                     "Час сканування вичерпано. Наявні докази збережено; перевірку не завершено.",
	"CANCELLED":                     "Запуск скасовано. Наявні докази збережено; перевірку не завершено.",
	"INVALID_LAUNCH_RESULT":         "Відповідь середовища запуску некоректна. Потрібен перегляд приватного запису.",
	"FINDINGS_REPORTED":             "Сканер завершився і повідомив про знахідки. Це не збій; потрібен ручний перегляд.",
	"COMPLETED":                     "Сканер завершився. Результат ще потребує перевірки та перегляду.",
}

func KnownDiagnosticCode(code string) bool { _, ok := diagnosticMessages[code]; return ok }
func DiagnosticMessage(code string) string {
	if message, ok := diagnosticMessages[code]; ok {
		return message
	}
	return "Потрібен перегляд приватного запису запуску; причина ще не визначена."
}
func stageFailureCode(s Stage) string {
	switch s {
	case StageState:
		return "STATE_CHECK_FAILED"
	case StageDatabase:
		return "DATABASE_CHECK_FAILED"
	case StageRules:
		return "RULES_CHECK_FAILED"
	case StageTool:
		return "TOOL_CHECK_FAILED"
	case StageApproval:
		return "APPROVAL_CHECK_FAILED"
	case StageIsolation:
		return "ISOLATION_CHECK_FAILED"
	default:
		return "DECLARATION_REJECTED"
	}
}

// DiagnosticArtifact is deliberately separate from native scanner results.
// Content is sensitive untrusted text, never a parser input or portable message.
type DiagnosticArtifact struct {
	Stream    string               `json:"stream"`
	Truncated bool                 `json:"truncated"`
	Artifact  artifact.RawArtifact `json:"artifact"`
}
