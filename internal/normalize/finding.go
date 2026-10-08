// Package normalize owns the canonical, deterministic finding representation.
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const SchemaVersion = "pao.dev/finding/v1alpha1"

var (
	findingIDPattern = regexp.MustCompile(`^finding-[a-z0-9][a-z0-9._:-]{0,127}$`)
	sha256RefPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Location struct {
	URI    string `json:"uri"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Finding struct {
	Version            string     `json:"version"`
	FindingID          string     `json:"finding_id"`
	StableFingerprint  string     `json:"stable_fingerprint"`
	Category           string     `json:"category"`
	Title              string     `json:"title"`
	Description        string     `json:"description,omitempty"`
	Status             string     `json:"status"`
	Severity           string     `json:"severity"`
	Confidence         string     `json:"confidence"`
	ScannerID          string     `json:"scanner_id"`
	ScannerVersion     string     `json:"scanner_version,omitempty"`
	RuleID             string     `json:"rule_id,omitempty"`
	DatabaseVersion    string     `json:"database_version,omitempty"`
	TargetID           string     `json:"target_id"`
	ConfigHash         string     `json:"config_hash,omitempty"`
	Locations          []Location `json:"locations,omitempty"`
	EvidenceRefs       []string   `json:"evidence_refs"`
	RawResultRef       string     `json:"raw_result_ref"`
	ToolExecutionID    string     `json:"tool_execution_id"`
	AssumptionIDs      []string   `json:"assumption_ids,omitempty"`
	CorrelationGroupID string     `json:"correlation_group_id,omitempty"`
}

func (f Finding) Validate() error {
	if f.Version != SchemaVersion {
		return fmt.Errorf("unsupported finding version: %q", f.Version)
	}
	if !findingIDPattern.MatchString(f.FindingID) || len(f.StableFingerprint) != 64 || f.Title == "" || f.ScannerID == "" || f.TargetID == "" || f.ToolExecutionID == "" || !sha256RefPattern.MatchString(f.RawResultRef) || (f.ConfigHash != "" && !sha256RefPattern.MatchString(f.ConfigHash)) {
		return errors.New("finding is missing a required identity or evidence field")
	}
	if _, err := hex.DecodeString(f.StableFingerprint); err != nil {
		return errors.New("finding stable fingerprint is not SHA-256 hex")
	}
	if !contains([]string{"inventory", "vulnerability", "license", "secret", "sast", "iac", "configuration", "provenance"}, f.Category) ||
		!contains([]string{"OPEN", "SUPPRESSED", "FIXED", "MANUAL_REVIEW", "CONFLICT"}, f.Status) ||
		!contains([]string{"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, f.Severity) ||
		!contains([]string{"LOW", "MEDIUM", "HIGH"}, f.Confidence) {
		return errors.New("finding contains an unsupported category, status, severity or confidence")
	}
	if len(f.EvidenceRefs) == 0 {
		return errors.New("finding requires evidence references")
	}
	for _, ref := range f.EvidenceRefs {
		if !sha256RefPattern.MatchString(ref) {
			return errors.New("finding has unsafe evidence reference")
		}
	}
	for _, location := range f.Locations {
		if location.URI == "" || strings.HasPrefix(location.URI, "/") || strings.Contains(location.URI, "..") || location.Line < 0 || location.Column < 0 {
			return errors.New("finding has unsafe location")
		}
	}
	return nil
}

// Fingerprint derives a stable identity only from explicitly supplied canonical fields.
func Fingerprint(fields ...string) string {
	hash := sha256.New()
	for _, field := range fields {
		hash.Write([]byte(field))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// CanonicalJSON sorts order-insensitive lists before serializing, providing byte-stable content
// for fixed evidence, toolchain and policy inputs.
func CanonicalJSON(f Finding) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	copy := f
	copy.EvidenceRefs = append([]string(nil), f.EvidenceRefs...)
	copy.AssumptionIDs = append([]string(nil), f.AssumptionIDs...)
	copy.Locations = append([]Location(nil), f.Locations...)
	sort.Strings(copy.EvidenceRefs)
	sort.Strings(copy.AssumptionIDs)
	sort.Slice(copy.Locations, func(i, j int) bool {
		if copy.Locations[i].URI != copy.Locations[j].URI {
			return copy.Locations[i].URI < copy.Locations[j].URI
		}
		if copy.Locations[i].Line != copy.Locations[j].Line {
			return copy.Locations[i].Line < copy.Locations[j].Line
		}
		return copy.Locations[i].Column < copy.Locations[j].Column
	})
	return json.Marshal(copy)
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
