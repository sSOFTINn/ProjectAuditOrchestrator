// Package report renders portable views from canonical findings. It never reads scanner output.
package report

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/normalize"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/policy"
)

type Input struct {
	Findings []normalize.Finding
	Decision policy.Decision
	AsOf     time.Time
}

func (input Input) Validate() error {
	if input.AsOf.IsZero() {
		return fmt.Errorf("report requires explicit as-of time")
	}
	for _, finding := range input.Findings {
		if err := finding.Validate(); err != nil {
			return err
		}
	}
	if input.Decision.ID == "" || input.Decision.Verdict == "" || input.Decision.PolicyDigest == "" || input.Decision.InputDigest == "" || input.Decision.DecisionDigest == "" {
		return fmt.Errorf("report requires a complete policy decision")
	}
	return nil
}

func JSONL(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, finding := range input.Findings {
		encoded, err := json.Marshal(portableFinding(finding))
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func Markdown(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# PAO portable audit report\n\nVerdict: `%s`  \nDecision: `%s`  \nPolicy digest: `%s`  \nInput digest: `%s`\n\n", input.Decision.Verdict, input.Decision.ID, input.Decision.PolicyDigest, input.Decision.InputDigest)
	out.WriteString("| Finding ID | Severity | Status | Title | Evidence |\n|---|---|---|---|---|\n")
	for _, finding := range input.Findings {
		portable := portableFinding(finding)
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s | %d protected reference(s) |\n", markdownCell(portable.FindingID), markdownCell(portable.Severity), markdownCell(portable.Status), markdownCell(portable.Title), portable.EvidenceCount)
	}
	return []byte(out.String()), nil
}

func SARIF(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   message           `json:"message"`
		PartialFP map[string]string `json:"partialFingerprints"`
	}
	results := make([]result, 0, len(input.Findings))
	for _, finding := range input.Findings {
		portable := portableFinding(finding)
		results = append(results, result{RuleID: portable.ScannerID, Level: sarifLevel(portable.Severity), Message: message{Text: portable.Title}, PartialFP: map[string]string{"pao/finding_id": portable.FindingID, "pao/stable_fingerprint": portable.StableFingerprint}})
	}
	payload := struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []result `json:"results"`
		} `json:"runs"`
	}{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json"}
	run := struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}{Results: results}
	run.Tool.Driver.Name = "PAO"
	payload.Runs = []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}{run}
	return json.MarshalIndent(payload, "", "  ")
}

func CycloneDX(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	type vulnerability struct {
		ID          string `json:"id"`
		Description string `json:"description,omitempty"`
	}
	vulnerabilities := make([]vulnerability, 0, len(input.Findings))
	for _, finding := range input.Findings {
		portable := portableFinding(finding)
		vulnerabilities = append(vulnerabilities, vulnerability{ID: portable.FindingID, Description: portable.Title})
	}
	payload := struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Component struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
	}{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + stableBundleUUID(input), Version: 1, Vulnerabilities: vulnerabilities}
	payload.Metadata.Timestamp = input.AsOf.UTC().Format(time.RFC3339)
	payload.Metadata.Component.Type, payload.Metadata.Component.Name = "application", "Project Audit Orchestrator portable report"
	return json.MarshalIndent(payload, "", "  ")
}

func SPDX(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	payload := struct {
		SPDXVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Comment string `json:"comment"`
	}{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "PAO portable finding report", DocumentNamespace: "https://pao.dev/spdx/" + stableBundleID(input)}
	payload.CreationInfo.Created = input.AsOf.UTC().Format(time.RFC3339)
	payload.CreationInfo.Creators = []string{"Tool: Project Audit Orchestrator"}
	payload.Comment = "Portable report from canonical PAO findings. Verdict=" + input.Decision.Verdict + "; findings=" + strings.Join(portableIDs(input.Findings), ",")
	return json.MarshalIndent(payload, "", "  ")
}

// PortableFinding has only trusted canonical identifiers and classifications. Scanner-controlled
// title, description, locations and raw/evidence addresses remain inside the protected boundary.
type PortableFinding struct {
	FindingID         string `json:"finding_id"`
	StableFingerprint string `json:"stable_fingerprint"`
	Category          string `json:"category"`
	Title             string `json:"title"`
	Status            string `json:"status"`
	Severity          string `json:"severity"`
	Confidence        string `json:"confidence"`
	ScannerID         string `json:"scanner_id"`
	TargetID          string `json:"target_id"`
	EvidenceCount     int    `json:"protected_evidence_count"`
}

func portableFinding(finding normalize.Finding) PortableFinding {
	return PortableFinding{
		FindingID:         finding.FindingID,
		StableFingerprint: finding.StableFingerprint,
		Category:          finding.Category,
		Title:             "Canonical finding " + finding.FindingID,
		Status:            finding.Status,
		Severity:          finding.Severity,
		Confidence:        finding.Confidence,
		ScannerID:         finding.ScannerID,
		TargetID:          finding.TargetID,
		EvidenceCount:     len(finding.EvidenceRefs),
	}
}

func markdownCell(value string) string {
	return strings.NewReplacer("|", "\\|", "\r\n", "<br>", "\n", "<br>", "\r", "<br>").Replace(value)
}

func sarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func stableBundleID(input Input) string {
	value := strings.TrimPrefix(input.Decision.InputDigest, "sha256:")
	if len(value) < 32 {
		return normalize.Fingerprint(value)[:32]
	}
	return value[:32]
}

// stableBundleUUID is a name-based UUID v5 in the RFC DNS namespace. SHA-1 is
// used only by the UUID algorithm, never as an integrity or approval digest.
// The entire input digest participates, rather than its first 128 bits.
func stableBundleUUID(input Input) string {
	dnsNamespace := [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New()
	_, _ = h.Write(dnsNamespace[:])
	_, _ = h.Write([]byte("pao.dev/portable-report/" + input.Decision.InputDigest))
	uuid := h.Sum(nil)[:16]
	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func portableIDs(findings []normalize.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.FindingID)
	}
	return ids
}
