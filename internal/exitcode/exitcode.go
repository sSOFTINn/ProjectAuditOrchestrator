// Package exitcode keeps CI outcome mappings stable and independent of presentation text.
package exitcode

const (
	OK         = 0
	Error      = 1
	Usage      = 2
	Review     = 3
	Incomplete = 4
	Blocked    = 5
)

func ForVerdict(verdict string) int {
	switch verdict {
	case "PASS":
		return OK
	case "PASS_WITH_REVIEW":
		return Review
	case "INCOMPLETE":
		return Incomplete
	case "BLOCKED":
		return Blocked
	default:
		return Error
	}
}
