// Package policy evaluates deterministic local policy from canonical evidence only.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

type Policy struct {
	ID                      string `json:"id"`
	Version                 string `json:"version"`
	BlockAtOrAbove          string `json:"block_at_or_above"`
	RequireCompleteCoverage bool   `json:"require_complete_coverage"`
}

type Waiver struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Reason    string    `json:"reason"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ReviewID  string    `json:"review_id"`
}

func (w Waiver) Validate(asOf time.Time) error {
	if w.ID == "" || w.Owner == "" || w.Reason == "" || w.Scope == "" || w.ReviewID == "" || w.CreatedAt.IsZero() || w.ExpiresAt.IsZero() {
		return errors.New("waiver requires ID, owner, reason, scope, dates and manual review ID")
	}
	if !w.ExpiresAt.After(w.CreatedAt) || !w.ExpiresAt.After(asOf) {
		return errors.New("waiver is expired or has invalid date range")
	}
	if !strings.HasPrefix(w.Scope, "finding:") && !strings.HasPrefix(w.Scope, "fingerprint:") {
		return errors.New("waiver scope must be an exact finding or fingerprint selector")
	}
	return nil
}

type Decision struct {
	ID             string `json:"id"`
	Verdict        string `json:"verdict"`
	Explanation    string `json:"explanation"`
	PolicyDigest   string `json:"policy_digest"`
	InputDigest    string `json:"input_digest"`
	DecisionDigest string `json:"decision_digest"`
	WaiverID       string `json:"waiver_id,omitempty"`
}

func (p Policy) Evaluate(findings []normalize.Finding, coverage []toolchain.Coverage, waiver *Waiver, asOf time.Time) (Decision, error) {
	if p.ID == "" || p.Version == "" || severityRank(p.BlockAtOrAbove) < 0 {
		return Decision{}, errors.New("policy requires ID, version and valid blocking severity")
	}
	if waiver != nil {
		if err := waiver.Validate(asOf); err != nil {
			return Decision{}, err
		}
	}
	for _, finding := range findings {
		if err := finding.Validate(); err != nil {
			return Decision{}, fmt.Errorf("invalid canonical finding: %w", err)
		}
	}
	policyDigest, err := digest(p)
	if err != nil {
		return Decision{}, err
	}
	inputDigest, err := inputDigest(findings, coverage, waiver)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{ID: "decision:" + normalize.Fingerprint(p.ID, p.Version, inputDigest), PolicyDigest: policyDigest, InputDigest: inputDigest}
	if p.RequireCompleteCoverage && coverageIncomplete(coverage) {
		decision.Verdict, decision.Explanation = "INCOMPLETE", "one or more required capabilities are unavailable, partial or not completed"
	} else if blocked := blockedFindings(findings, p.BlockAtOrAbove); len(blocked) > 0 {
		if waiver == nil || !waiverAppliesToAll(*waiver, blocked) {
			decision.Verdict, decision.Explanation = "BLOCKED", "policy threshold exceeded without a valid waiver"
		} else {
			decision.Verdict, decision.Explanation, decision.WaiverID = "PASS_WITH_REVIEW", "policy threshold waived pending recorded human review", waiver.ID
		}
	} else if hasManualReview(findings) {
		decision.Verdict, decision.Explanation = "PASS_WITH_REVIEW", "canonical findings require human review"
	} else {
		decision.Verdict, decision.Explanation = "PASS", "all evaluated canonical findings are below the policy threshold"
	}
	withoutDigest := decision
	withoutDigest.DecisionDigest = ""
	decision.DecisionDigest, err = digest(withoutDigest)
	if err != nil {
		return Decision{}, err
	}
	return decision, nil
}

func inputDigest(findings []normalize.Finding, coverage []toolchain.Coverage, waiver *Waiver) (string, error) {
	findingBytes := make([]string, 0, len(findings))
	for _, finding := range findings {
		encoded, err := normalize.CanonicalJSON(finding)
		if err != nil {
			return "", err
		}
		findingBytes = append(findingBytes, string(encoded))
	}
	sort.Strings(findingBytes)
	coverageCopy := append([]toolchain.Coverage(nil), coverage...)
	sort.Slice(coverageCopy, func(i, j int) bool {
		if coverageCopy[i].ToolID != coverageCopy[j].ToolID {
			return coverageCopy[i].ToolID < coverageCopy[j].ToolID
		}
		return coverageCopy[i].Capability < coverageCopy[j].Capability
	})
	payload := struct {
		Findings []string             `json:"findings"`
		Coverage []toolchain.Coverage `json:"coverage"`
		Waiver   *Waiver              `json:"waiver,omitempty"`
	}{findingBytes, coverageCopy, waiver}
	return digest(payload)
}

func coverageIncomplete(coverage []toolchain.Coverage) bool {
	if len(coverage) == 0 {
		return true
	}
	for _, item := range coverage {
		if !item.Complete() {
			return true
		}
	}
	return false
}

func hasManualReview(findings []normalize.Finding) bool {
	for _, finding := range findings {
		if finding.Status == "MANUAL_REVIEW" || finding.Severity == "UNKNOWN" {
			return true
		}
	}
	return false
}

func blockedFindings(findings []normalize.Finding, threshold string) []normalize.Finding {
	thresholdRank := severityRank(threshold)
	blocked := make([]normalize.Finding, 0)
	for _, finding := range findings {
		if severityRank(finding.Severity) >= thresholdRank {
			blocked = append(blocked, finding)
		}
	}
	return blocked
}

func waiverAppliesToAll(waiver Waiver, findings []normalize.Finding) bool {
	for _, finding := range findings {
		switch {
		case strings.HasPrefix(waiver.Scope, "finding:"):
			if strings.TrimPrefix(waiver.Scope, "finding:") != finding.FindingID {
				return false
			}
		case strings.HasPrefix(waiver.Scope, "fingerprint:"):
			if strings.TrimPrefix(waiver.Scope, "fingerprint:") != finding.StableFingerprint {
				return false
			}
		default:
			return false
		}
	}
	return len(findings) > 0
}

func severityRank(value string) int {
	switch value {
	case "INFO":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return -1
	}
}

func digest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}
