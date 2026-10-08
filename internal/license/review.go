// Package license retains scanner-observed SPDX text and makes ambiguity explicit.
// It intentionally does not provide legal advice or choose between alternatives.
package license

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

const (
	StatusObserved     = "OBSERVED"
	StatusManualReview = "MANUAL_REVIEW"
)

var (
	spdxToken = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)
	sha256Ref = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	knownIDs  = map[string]bool{"Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "CC0-1.0": true, "GPL-2.0-only": true, "GPL-2.0-or-later": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true, "ISC": true, "LGPL-2.1-only": true, "LGPL-2.1-or-later": true, "LGPL-3.0-only": true, "LGPL-3.0-or-later": true, "MIT": true, "MPL-2.0": true, "Unlicense": true}
)

// Observation is an evidence-backed, exact scanner assertion. SPDXExpression is
// retained unchanged; SelectedExpression is never derived by this package.
type Observation struct {
	ComponentID        string   `json:"component_id"`
	SPDXExpression     string   `json:"spdx_expression"`
	EvidenceRefs       []string `json:"evidence_refs"`
	SelectedExpression string   `json:"selected_expression,omitempty"`
	SelectionBasis     string   `json:"selection_basis,omitempty"`
	Status             string   `json:"status"`
}

type ReviewItem struct {
	ComponentID    string   `json:"component_id"`
	SPDXExpression string   `json:"spdx_expression"`
	Reasons        []string `json:"reasons"`
	EvidenceRefs   []string `json:"evidence_refs"`
	Status         string   `json:"status"`
}

func (o Observation) Validate() error {
	if o.ComponentID == "" || o.SPDXExpression == "" || strings.ContainsRune(o.SPDXExpression, '\x00') {
		return errors.New("license observation requires a component and exact SPDX expression")
	}
	if len(o.EvidenceRefs) == 0 {
		return errors.New("license observation requires protected evidence")
	}
	for _, ref := range o.EvidenceRefs {
		if !sha256Ref.MatchString(ref) {
			return errors.New("license evidence reference must be SHA-256 addressed")
		}
	}
	if o.SelectedExpression != "" && o.SelectionBasis == "" {
		return errors.New("selected license requires documented election basis")
	}
	if o.SelectedExpression == "" && o.SelectionBasis != "" {
		return errors.New("license selection basis requires an explicit selected expression")
	}
	if o.Status != StatusObserved && o.Status != StatusManualReview {
		return errors.New("license observation has unsupported status")
	}
	return nil
}

// Queue returns the exact observed expression with reasons whenever automated
// handling would conceal an ambiguity. It is deliberately conservative.
func Queue(observations []Observation) ([]ReviewItem, error) {
	queue := make([]ReviewItem, 0)
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return nil, err
		}
		reasons := reviewReasons(observation)
		if len(reasons) == 0 {
			continue
		}
		evidence := append([]string(nil), observation.EvidenceRefs...)
		sort.Strings(evidence)
		queue = append(queue, ReviewItem{ComponentID: observation.ComponentID, SPDXExpression: observation.SPDXExpression, Reasons: reasons, EvidenceRefs: evidence, Status: StatusManualReview})
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].ComponentID < queue[j].ComponentID })
	return queue, nil
}

func reviewReasons(observation Observation) []string {
	expression := observation.SPDXExpression
	upper := strings.ToUpper(expression)
	reasons := make([]string, 0)
	if expression == "NOASSERTION" {
		reasons = append(reasons, "NOASSERTION")
	}
	if strings.Contains(expression, "LicenseRef-") || strings.Contains(expression, "DocumentRef-") {
		reasons = append(reasons, "CUSTOM_LICENSE_REFERENCE")
	}
	if strings.Contains(upper, " OR ") && (observation.SelectedExpression == "" || observation.SelectionBasis == "") {
		reasons = append(reasons, "DUAL_LICENSE_WITHOUT_ELECTION_BASIS")
	}
	for _, token := range strings.FieldsFunc(strings.ReplaceAll(strings.ReplaceAll(expression, "(", " "), ")", " "), func(r rune) bool { return r == ' ' || r == '+' }) {
		if strings.EqualFold(token, "AND") || strings.EqualFold(token, "OR") || strings.EqualFold(token, "WITH") || token == "NOASSERTION" || strings.HasPrefix(token, "LicenseRef-") || strings.HasPrefix(token, "DocumentRef-") {
			continue
		}
		if !spdxToken.MatchString(token) || !knownIDs[token] {
			reasons = append(reasons, "UNKNOWN_SPDX_IDENTIFIER")
			break
		}
	}
	return reasons
}
