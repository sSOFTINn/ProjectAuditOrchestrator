// Package correlate groups equivalent canonical findings without deleting their evidence.
package correlate

import (
	"sort"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
)

type Group struct {
	ID                string   `json:"id"`
	StableFingerprint string   `json:"stable_fingerprint"`
	FindingIDs        []string `json:"finding_ids"`
	Relationship      string   `json:"relationship"`
}

// GroupEquivalent creates deterministic groups for identical canonical fingerprints. Each
// original finding remains present in the returned slice and only gains a group reference.
func GroupEquivalent(findings []normalize.Finding) ([]normalize.Finding, []Group) {
	copy := append([]normalize.Finding(nil), findings...)
	byFingerprint := make(map[string][]int)
	for index := range copy {
		byFingerprint[copy[index].StableFingerprint] = append(byFingerprint[copy[index].StableFingerprint], index)
	}
	fingerprints := make([]string, 0, len(byFingerprint))
	for fingerprint := range byFingerprint {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	groups := make([]Group, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		indexes := byFingerprint[fingerprint]
		if len(indexes) < 2 {
			continue
		}
		ids := make([]string, 0, len(indexes))
		for _, index := range indexes {
			ids = append(ids, copy[index].FindingID)
		}
		sort.Strings(ids)
		groupID := "correlation:" + normalize.Fingerprint("equivalent", fingerprint)
		for _, index := range indexes {
			copy[index].CorrelationGroupID = groupID
		}
		groups = append(groups, Group{ID: groupID, StableFingerprint: fingerprint, FindingIDs: ids, Relationship: "EQUIVALENT"})
	}
	return copy, groups
}
