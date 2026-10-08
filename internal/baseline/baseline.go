// Package baseline compares canonical finding identities without retaining raw evidence twice.
package baseline

import (
	"sort"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
)

type Snapshot struct {
	FindingFingerprints []string `json:"finding_fingerprints"`
}

type Diff struct {
	New       []string `json:"new"`
	Resolved  []string `json:"resolved"`
	Unchanged []string `json:"unchanged"`
}

func FromFindings(findings []normalize.Finding) Snapshot {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		seen[finding.StableFingerprint] = struct{}{}
	}
	items := make([]string, 0, len(seen))
	for fingerprint := range seen {
		items = append(items, fingerprint)
	}
	sort.Strings(items)
	return Snapshot{FindingFingerprints: items}
}

func Compare(base, current Snapshot) Diff {
	baseSet, currentSet := toSet(base.FindingFingerprints), toSet(current.FindingFingerprints)
	diff := Diff{}
	for fingerprint := range currentSet {
		if _, exists := baseSet[fingerprint]; exists {
			diff.Unchanged = append(diff.Unchanged, fingerprint)
		} else {
			diff.New = append(diff.New, fingerprint)
		}
	}
	for fingerprint := range baseSet {
		if _, exists := currentSet[fingerprint]; !exists {
			diff.Resolved = append(diff.Resolved, fingerprint)
		}
	}
	sort.Strings(diff.New)
	sort.Strings(diff.Resolved)
	sort.Strings(diff.Unchanged)
	return diff
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}
