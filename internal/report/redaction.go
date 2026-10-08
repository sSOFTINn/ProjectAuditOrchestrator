package report

import "regexp"

var (
	syntheticSecret  = regexp.MustCompile(`PAO_SYNTHETIC_SECRET_[A-Za-z0-9_]+`)
	assignmentSecret = regexp.MustCompile(`(?i)\b(api[_-]?key|token|password)\s*[:=]\s*[^\s,;]+`)
	emailAddress     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

// Redact removes known synthetic test secrets, common inline credentials and email-like PII from
// portable outputs. Raw evidence remains protected in the artifact store.
func Redact(value string) string {
	value = syntheticSecret.ReplaceAllString(value, "[REDACTED_SECRET]")
	value = assignmentSecret.ReplaceAllString(value, "$1=[REDACTED_SECRET]")
	return emailAddress.ReplaceAllString(value, "[REDACTED_EMAIL]")
}
