package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

var decisionDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// DecisionRecord is the complete, reprocessable policy evidence set. It has no
// implicit current-policy lookup: policy, coverage, waiver and assumptions are
// persisted with the result that they produced.
type DecisionRecord struct {
	Policy               Policy               `json:"policy"`
	Findings             []normalize.Finding  `json:"findings"`
	Coverage             []toolchain.Coverage `json:"coverage"`
	Waiver               *Waiver              `json:"waiver,omitempty"`
	AssumptionIDs        []string             `json:"assumption_ids"`
	VerifierEvidenceRefs []string             `json:"verifier_evidence_refs"`
	Decision             Decision             `json:"decision"`
}

func (r DecisionRecord) Validate() error {
	if r.Policy.ID == "" || r.Policy.Version == "" || r.Decision.ID == "" || !decisionDigest.MatchString(r.Decision.PolicyDigest) || !decisionDigest.MatchString(r.Decision.InputDigest) || !decisionDigest.MatchString(r.Decision.DecisionDigest) {
		return errors.New("decision record is missing policy or digest lineage")
	}
	if len(r.Coverage) == 0 || len(r.VerifierEvidenceRefs) == 0 {
		return errors.New("decision record requires coverage and verifier evidence")
	}
	for _, ref := range r.VerifierEvidenceRefs {
		if !decisionDigest.MatchString(ref) {
			return errors.New("verifier evidence must be SHA-256 addressed")
		}
	}
	return nil
}

type DecisionStore struct{ root string }

func OpenDecisionStore(root string) (*DecisionStore, error) {
	if root == "" {
		return nil, errors.New("decision store root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve decision store: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create decision store: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("decision store root must be a real directory")
	}
	return &DecisionStore{root: abs}, nil
}

// Save writes a canonical record once at the content-derived decision address.
// Existing records are byte-compared and never silently replaced.
func (s *DecisionStore) Save(record DecisionRecord) (string, error) {
	if s == nil || s.root == "" {
		return "", errors.New("decision store is not open")
	}
	if err := record.Validate(); err != nil {
		return "", err
	}
	canonical := record
	canonical.Findings = append([]normalize.Finding(nil), record.Findings...)
	canonical.Coverage = append([]toolchain.Coverage(nil), record.Coverage...)
	canonical.AssumptionIDs = append([]string(nil), record.AssumptionIDs...)
	canonical.VerifierEvidenceRefs = append([]string(nil), record.VerifierEvidenceRefs...)
	sort.Strings(canonical.AssumptionIDs)
	sort.Strings(canonical.VerifierEvidenceRefs)
	sort.Slice(canonical.Coverage, func(i, j int) bool { return canonical.Coverage[i].ToolID < canonical.Coverage[j].ToolID })
	sort.Slice(canonical.Findings, func(i, j int) bool { return canonical.Findings[i].FindingID < canonical.Findings[j].FindingID })
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode decision record: %w", err)
	}
	name := record.Decision.DecisionDigest[len("sha256:"):] + ".json"
	path := filepath.Join(s.root, name)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("decision record address is not a regular file")
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if string(existing) != string(encoded) {
			return "", errors.New("decision digest collision or attempted overwrite")
		}
		return filepath.ToSlash(name), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		return "", fmt.Errorf("write immutable decision record: %w", err)
	}
	return filepath.ToSlash(name), nil
}
