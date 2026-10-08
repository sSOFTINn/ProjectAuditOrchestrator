// Package toolchain validates user-supplied scanner identities and records explicit coverage.
package toolchain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type Record struct {
	ID                  string            `json:"id"`
	Version             string            `json:"version"`
	SHA256              string            `json:"sha256"`
	SourceLicense       string            `json:"source_license"`
	Redistribution      string            `json:"redistribution"`
	DatabaseSHA256      string            `json:"database_sha256,omitempty"`
	DatabaseAt          time.Time         `json:"database_at,omitempty"`
	DatabaseEnvironment map[string]string `json:"database_environment,omitempty"`
	StateSHA256         string            `json:"state_sha256,omitempty"`
	StateAt             time.Time         `json:"state_at,omitempty"`
	StateEnvironment    map[string]string `json:"state_environment,omitempty"`
	RuntimeSHA256       string            `json:"runtime_sha256,omitempty"`
	RuntimeAt           time.Time         `json:"runtime_at,omitempty"`
	RulePackSHA256      string            `json:"rule_pack_sha256,omitempty"`
	RulePackAt          time.Time         `json:"rule_pack_at,omitempty"`
	LicenseDataSHA256   string            `json:"license_data_sha256,omitempty"`
	LicenseDataAt       time.Time         `json:"license_data_at,omitempty"`
}

type Requirement struct {
	ToolID                string
	Capability            string
	RequiresDatabase      bool
	MaximumDatabaseAge    time.Duration
	RequiresState         bool
	MaximumStateAge       time.Duration
	RequiresRuntime       bool
	MaximumRuntimeAge     time.Duration
	RequiresRulePack      bool
	MaximumRulePackAge    time.Duration
	RequiresLicenseData   bool
	MaximumLicenseDataAge time.Duration
}

// MaximumPrerequisiteAge applies the owner's 90-day freshness policy to
// prerequisite approvals at execution time.
const MaximumPrerequisiteAge = 90 * 24 * time.Hour

type Coverage struct {
	ToolID     string `json:"tool_id"`
	Capability string `json:"capability"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
	Reason     string `json:"reason"`
}

const (
	ReasonNotApplicable                = "SKIPPED_NOT_APPLICABLE"
	ReasonDatabaseEcosystemUnsupported = "DB_ECOSYSTEM_UNSUPPORTED"
	ReasonEcosystemUnsupported         = "ECOSYSTEM_UNSUPPORTED"
	ReasonUnsupportedInputFormat       = "UNSUPPORTED_INPUT_FORMAT"
	ReasonToolMissing                  = "TOOL_MISSING"
	ReasonToolUnverified               = "TOOL_UNVERIFIED"
	ReasonDatabaseMissing              = "DB_MISSING"
	ReasonDatabaseStale                = "DB_STALE"
	ReasonStateMissing                 = "STATE_MISSING"
	ReasonStateStale                   = "STATE_STALE"
	ReasonRuntimeMissing               = "RUNTIME_MISSING"
	ReasonRuntimeStale                 = "RUNTIME_STALE"
	ReasonRulePackMissing              = "RULE_PACK_MISSING"
	ReasonRulePackStale                = "RULE_PACK_STALE"
	ReasonLicenseDataMissing           = "LICENSE_DATA_MISSING"
	ReasonLicenseDataStale             = "LICENSE_DATA_STALE"
	ReasonIsolationMismatch            = "ISOLATION_MISMATCH"
	ReasonMalformedOutput              = "MALFORMED_OUTPUT"
	ReasonTimedOut                     = "TIMED_OUT"
)

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Complete is intentionally narrow: a coverage limitation never becomes a clean audit result.
func (c Coverage) Complete() bool { return c.Status == "SUCCEEDED" || c.Status == "NO_FINDINGS" }

func (c Coverage) Validate() error {
	if c.ToolID == "" || c.Capability == "" || c.Status == "" || c.Reason == "" {
		return errors.New("coverage requires tool, capability, status and reason")
	}
	if c.ReasonCode != "" && !knownReason(c.ReasonCode) {
		return fmt.Errorf("unknown coverage reason code: %s", c.ReasonCode)
	}
	return nil
}

func knownReason(code string) bool {
	switch code {
	case ReasonNotApplicable, ReasonDatabaseEcosystemUnsupported, ReasonEcosystemUnsupported, ReasonUnsupportedInputFormat, ReasonToolMissing, ReasonToolUnverified, ReasonDatabaseMissing, ReasonDatabaseStale, ReasonStateMissing, ReasonStateStale, ReasonRuntimeMissing, ReasonRuntimeStale, ReasonRulePackMissing, ReasonRulePackStale, ReasonLicenseDataMissing, ReasonLicenseDataStale, ReasonIsolationMismatch, ReasonMalformedOutput, ReasonTimedOut:
		return true
	default:
		return false
	}
}

// ExplicitGap builds a non-pass coverage record for a named prerequisite failure.
// It is intentionally not used for successful execution: each limitation must stay visible.
func ExplicitGap(toolID, capability, reasonCode, reason string) (Coverage, error) {
	if !knownReason(reasonCode) || reason == "" {
		return Coverage{}, errors.New("known coverage reason code and reason are required")
	}
	status := "UNAVAILABLE"
	if reasonCode == ReasonDatabaseStale || reasonCode == ReasonStateStale || reasonCode == ReasonRuntimeStale || reasonCode == ReasonRulePackStale || reasonCode == ReasonLicenseDataStale || reasonCode == ReasonMalformedOutput {
		status = "PARTIAL"
	}
	if reasonCode == ReasonIsolationMismatch {
		status = "POLICY_BLOCKED"
	}
	if reasonCode == ReasonTimedOut {
		status = "TIMED_OUT"
	}
	coverage := Coverage{ToolID: toolID, Capability: capability, Status: status, ReasonCode: reasonCode, Reason: reason}
	return coverage, coverage.Validate()
}

type Registry struct {
	records map[string]Record
}

// VersionForDigest reads catalog metadata only for the exact recorded tool bytes.
// It grants no approval and exposes no mutable registry state.
func (r *Registry) VersionForDigest(toolID, digest string) (string, error) {
	if r == nil {
		return "", errors.New("tool catalog unavailable")
	}
	if err := r.VerifyToolDigest(toolID, digest); err != nil {
		return "", err
	}
	return r.records[toolID].Version, nil
}

func New(records []Record) (*Registry, error) {
	r := &Registry{records: make(map[string]Record, len(records))}
	for _, record := range records {
		if err := validateRecord(record); err != nil {
			return nil, err
		}
		if _, exists := r.records[record.ID]; exists {
			return nil, fmt.Errorf("duplicate toolchain record: %s", record.ID)
		}
		if record.StateEnvironment != nil {
			copy := make(map[string]string, len(record.StateEnvironment))
			for name, value := range record.StateEnvironment {
				copy[name] = value
			}
			record.StateEnvironment = copy
		}
		if record.DatabaseEnvironment != nil {
			copy := make(map[string]string, len(record.DatabaseEnvironment))
			for name, value := range record.DatabaseEnvironment {
				copy[name] = value
			}
			record.DatabaseEnvironment = copy
		}
		r.records[record.ID] = record
	}
	return r, nil
}

func validateRecord(record Record) error {
	if record.ID == "" || record.Version == "" || record.SourceLicense == "" || record.Redistribution == "" {
		return errors.New("toolchain record requires ID, version, license and redistribution mode")
	}
	if !isSHA256(record.SHA256) {
		return fmt.Errorf("toolchain record %s has invalid SHA-256", record.ID)
	}
	if record.DatabaseSHA256 != "" && !isSHA256(record.DatabaseSHA256) {
		return fmt.Errorf("toolchain record %s has invalid database SHA-256", record.ID)
	}
	if record.StateSHA256 != "" && !isSHA256(record.StateSHA256) {
		return fmt.Errorf("toolchain record %s has invalid prepared-state SHA-256", record.ID)
	}
	for label, digest := range map[string]string{"runtime": record.RuntimeSHA256, "rule pack": record.RulePackSHA256, "license data": record.LicenseDataSHA256} {
		if digest != "" && !isSHA256(digest) {
			return fmt.Errorf("toolchain record %s has invalid %s SHA-256", record.ID, label)
		}
	}
	for label, values := range map[string]map[string]string{"database": record.DatabaseEnvironment, "prepared-state": record.StateEnvironment} {
		for name, value := range values {
			if !environmentName.MatchString(name) || value == "" || strings.ContainsRune(value, '\x00') {
				return fmt.Errorf("toolchain record %s has unsafe %s environment: %s", record.ID, label, name)
			}
		}
	}
	return nil
}

func (r *Registry) Preflight(requirement Requirement, now time.Time) Coverage {
	coverage := Coverage{ToolID: requirement.ToolID, Capability: requirement.Capability}
	if r == nil {
		coverage.Status, coverage.ReasonCode, coverage.Reason = "UNAVAILABLE", ReasonToolMissing, "toolchain registry is unavailable"
		return coverage
	}
	record, found := r.records[requirement.ToolID]
	if !found {
		coverage.Status, coverage.ReasonCode, coverage.Reason = "UNAVAILABLE", ReasonToolUnverified, "no verified toolchain record"
		return coverage
	}
	if requirement.RequiresDatabase {
		if record.DatabaseSHA256 == "" || record.DatabaseAt.IsZero() {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonDatabaseMissing, "database identity or timestamp is missing"
			return coverage
		}
		if record.DatabaseAt.After(now) || (requirement.MaximumDatabaseAge > 0 && now.Sub(record.DatabaseAt) > requirement.MaximumDatabaseAge) {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonDatabaseStale, "database timestamp is future-dated or stale"
			return coverage
		}
	}
	if requirement.RequiresState {
		if record.StateSHA256 == "" || record.StateAt.IsZero() {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonStateMissing, "prepared state identity or timestamp is missing"
			return coverage
		}
		if record.StateAt.After(now) || (requirement.MaximumStateAge > 0 && now.Sub(record.StateAt) > requirement.MaximumStateAge) {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonStateStale, "prepared-state timestamp is future-dated or stale"
			return coverage
		}
	}
	if requirement.RequiresRuntime {
		if record.RuntimeSHA256 == "" || record.RuntimeAt.IsZero() {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonRuntimeMissing, "runtime identity or timestamp is missing"
			return coverage
		}
		if record.RuntimeAt.After(now) || (requirement.MaximumRuntimeAge > 0 && now.Sub(record.RuntimeAt) > requirement.MaximumRuntimeAge) {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonRuntimeStale, "runtime approval is future-dated or stale"
			return coverage
		}
	}
	if requirement.RequiresRulePack {
		if record.RulePackSHA256 == "" || record.RulePackAt.IsZero() {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonRulePackMissing, "rule-pack identity or timestamp is missing"
			return coverage
		}
		if record.RulePackAt.After(now) || (requirement.MaximumRulePackAge > 0 && now.Sub(record.RulePackAt) > requirement.MaximumRulePackAge) {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonRulePackStale, "rule-pack timestamp is future-dated or stale"
			return coverage
		}
	}
	if requirement.RequiresLicenseData {
		if record.LicenseDataSHA256 == "" || record.LicenseDataAt.IsZero() {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonLicenseDataMissing, "license-data identity or timestamp is missing"
			return coverage
		}
		if record.LicenseDataAt.After(now) || (requirement.MaximumLicenseDataAge > 0 && now.Sub(record.LicenseDataAt) > requirement.MaximumLicenseDataAge) {
			coverage.Status, coverage.ReasonCode, coverage.Reason = "PARTIAL", ReasonLicenseDataStale, "license-data timestamp is future-dated or stale"
			return coverage
		}
	}
	coverage.Status, coverage.Reason = "AVAILABLE_NOT_STARTED", "verified toolchain record"
	return coverage
}

// VerifyFile checks an already installed binary. It does not install, update or execute it.
func (r *Registry) VerifyFile(toolID, path string) error {
	if r == nil {
		return errors.New("toolchain registry is unavailable")
	}
	record, found := r.records[toolID]
	if !found {
		return fmt.Errorf("no toolchain record for %s", toolID)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read tool binary: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash tool binary: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), record.SHA256) {
		return fmt.Errorf("tool binary checksum mismatch for %s", toolID)
	}
	return nil
}

func (r *Registry) VerifyToolDigest(toolID, digest string) error {
	return r.verifyApprovedDigest(toolID, "tool", digest, func(record Record) string { return record.SHA256 })
}

func (r *Registry) VerifyDatabase(toolID, digest string, environment map[string]string) error {
	if err := r.verifyApprovedDigest(toolID, "database", digest, func(record Record) string { return record.DatabaseSHA256 }); err != nil {
		return err
	}
	record := r.records[toolID]
	if len(record.DatabaseEnvironment) != len(environment) {
		return fmt.Errorf("database environment does not match approved record for %s", toolID)
	}
	for name, expected := range record.DatabaseEnvironment {
		if environment[name] != expected {
			return fmt.Errorf("database environment does not match approved record for %s", toolID)
		}
	}
	return nil
}

// VerifyStateDigest binds an execution's verified prepared-state manifest to the
// approved state identity for its tool. It does not read, create or execute state.
func (r *Registry) VerifyStateDigest(toolID, stateDigest string) error {
	if r == nil {
		return errors.New("toolchain registry is unavailable")
	}
	record, found := r.records[toolID]
	if !found {
		return fmt.Errorf("no toolchain record for %s", toolID)
	}
	if record.StateSHA256 == "" {
		return fmt.Errorf("no approved prepared-state digest for %s", toolID)
	}
	if stateDigest != "sha256:"+record.StateSHA256 {
		return fmt.Errorf("prepared-state checksum mismatch for %s", toolID)
	}
	return nil
}

// VerifyPreparedState binds a declared state digest and its complete sanitized
// environment to an approved toolchain record before the isolation host launches.
func (r *Registry) VerifyPreparedState(toolID, stateDigest string, environment map[string]string) error {
	if err := r.VerifyStateDigest(toolID, stateDigest); err != nil {
		return err
	}
	record := r.records[toolID]
	if len(record.StateEnvironment) != len(environment) {
		return fmt.Errorf("prepared-state environment does not match approved record for %s", toolID)
	}
	for name, expected := range record.StateEnvironment {
		if environment[name] != expected {
			return fmt.Errorf("prepared-state environment does not match approved record for %s", toolID)
		}
	}
	return nil
}

func (r *Registry) VerifyRuntimeDigest(toolID, digest string) error {
	return r.verifyApprovedDigest(toolID, "runtime", digest, func(record Record) string { return record.RuntimeSHA256 })
}

func (r *Registry) VerifyRulePackDigest(toolID, digest string) error {
	return r.verifyApprovedDigest(toolID, "rule pack", digest, func(record Record) string { return record.RulePackSHA256 })
}

func (r *Registry) VerifyLicenseDataDigest(toolID, digest string) error {
	return r.verifyApprovedDigest(toolID, "license data", digest, func(record Record) string { return record.LicenseDataSHA256 })
}

func (r *Registry) verifyApprovedDigest(toolID, label, digest string, selectDigest func(Record) string) error {
	if r == nil {
		return errors.New("toolchain registry is unavailable")
	}
	record, found := r.records[toolID]
	if !found {
		return fmt.Errorf("no toolchain record for %s", toolID)
	}
	expected := selectDigest(record)
	if expected == "" {
		return fmt.Errorf("no approved %s digest for %s", label, toolID)
	}
	if digest != "sha256:"+expected {
		return fmt.Errorf("%s checksum mismatch for %s", label, toolID)
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
