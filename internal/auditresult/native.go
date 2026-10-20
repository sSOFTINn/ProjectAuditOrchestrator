// Package auditresult projects protected scanner evidence into an honest local report.
// Native output is untrusted data, never configuration, instructions or a verdict.
package auditresult

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxItems = 10000
const maxRawBytes = 64 << 20

// nativeItem deliberately excludes scanner messages, source lines, secrets and authors.
// Component, Path and Rule are private, scanner-reported metadata, not portable text.
type nativeItem struct {
	Category           string   `json:"category"`
	Rule               string   `json:"rule,omitempty"`
	Severity           string   `json:"severity"`
	NativeSeverity     string   `json:"native_severity,omitempty"`
	Component          string   `json:"component,omitempty"`
	ComponentVersion   string   `json:"component_version,omitempty"`
	PURL               string   `json:"purl,omitempty"`
	Path               string   `json:"path,omitempty"`
	Line               int      `json:"line,omitempty"`
	FixedVersions      []string `json:"scanner_reported_fixed_versions,omitempty"`
	Expression         string   `json:"observed_license_expression,omitempty"`
	ReviewReason       string   `json:"review_reason,omitempty"`
	SourcePointer      string   `json:"source_json_pointer,omitempty"`
	ComponentType      string   `json:"component_type,omitempty"`
	ComponentNamespace string   `json:"component_namespace,omitempty"`
	PackageUID         string   `json:"scanner_package_uid,omitempty"`
	ForPackageUID      string   `json:"scanner_parent_package_uid,omitempty"`
	DependencyUID      string   `json:"scanner_dependency_uid,omitempty"`
	Requirement        string   `json:"scanner_reported_requirement,omitempty"`
	Scope              string   `json:"scanner_reported_scope,omitempty"`
	DatafilePaths      []string `json:"scanner_datafile_paths,omitempty"`
	DatasourceIDs      []string `json:"scanner_datasource_ids,omitempty"`
	IsRuntime          *bool    `json:"scanner_is_runtime,omitempty"`
	IsOptional         *bool    `json:"scanner_is_optional,omitempty"`
	IsPinned           *bool    `json:"scanner_is_pinned,omitempty"`
	IsDirect           *bool    `json:"scanner_is_direct,omitempty"`
}

type parsed struct {
	Status                    string
	Reasons                   []string
	Items                     []nativeItem
	GoModuleFileCatalogerUsed bool
}

func (p *parsed) gap(code string) {
	p.Status = "PARTIAL"
	for _, r := range p.Reasons {
		if r == code {
			return
		}
	}
	p.Reasons = append(p.Reasons, code)
}

func (p *parsed) add(i nativeItem) {
	if len(p.Items) >= maxItems {
		p.gap("RESULT_LIMIT")
		return
	}
	for _, s := range i.textValues() {
		if len(s) > 8192 || strings.ContainsRune(s, 0) {
			p.gap("INVALID_ITEM")
			return
		}
	}
	if i.Severity == "" {
		i.Severity = "UNKNOWN"
	}
	p.Items = append(p.Items, i)
}

func (i nativeItem) textValues() []string {
	out := []string{i.Rule, i.Component, i.ComponentVersion, i.Path, i.PURL, i.Expression, i.NativeSeverity, i.ReviewReason, i.SourcePointer, i.ComponentType, i.ComponentNamespace, i.PackageUID, i.ForPackageUID, i.DependencyUID, i.Requirement, i.Scope}
	out = append(out, i.FixedVersions...)
	out = append(out, i.DatafilePaths...)
	return append(out, i.DatasourceIDs...)
}

// decodeJSON rejects duplicate keys, trailing documents, invalid UTF-8 and excessive
// nesting/token counts before any shape-specific interpretation. Unknown fields may
// be ignored, but never allowed to conceal malformed JSON or known error markers.
func decodeJSON(data []byte) (any, error) {
	if len(data) > maxRawBytes || !utf8.Valid(data) {
		return nil, errors.New("input limit or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	budget := 1000000
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		budget--
		if budget < 0 || depth > 64 {
			return nil, errors.New("JSON complexity limit")
		}
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, e
				}
				k, ok := key.(string)
				if !ok {
					return nil, errors.New("key type")
				}
				if _, exists := m[k]; exists {
					return nil, errors.New("duplicate key")
				}
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				m[k] = v
			}
			_, err = d.Token()
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, err = d.Token()
			return a, err
		default:
			return nil, errors.New("unexpected delimiter")
		}
	}
	v, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}

func obj(v any) map[string]any              { m, _ := v.(map[string]any); return m }
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func severity(s string) string {
	s = strings.ToUpper(s)
	if s == "INFORMATIONAL" {
		return "INFO"
	}
	switch s {
	case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return s
	}
	return "UNKNOWN"
}
func (p *parsed) array(m map[string]any, k string, required bool) []any {
	v, exists := m[k]
	if !exists {
		if required {
			p.gap("MISSING_RESULT_FIELD")
		}
		return nil
	}
	if v == nil && !required {
		return nil
	}
	a, ok := v.([]any)
	if !ok {
		p.gap("INVALID_RESULT_FIELD")
	}
	return a
}
func (p *parsed) rows(a []any, f func(map[string]any)) {
	for _, v := range a {
		if len(p.Items) >= maxItems {
			p.gap("RESULT_LIMIT")
			return
		}
		m := obj(v)
		if m == nil {
			p.gap("INVALID_ITEM")
			continue
		}
		f(m)
	}
}
func (p *parsed) require(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if str(m, k) == "" {
			p.gap("INVALID_ITEM")
			return false
		}
	}
	return true
}
func (p *parsed) line(m map[string]any, k string) int {
	v, exists := m[k]
	if !exists {
		return 0
	}
	n, ok := v.(json.Number)
	if !ok {
		p.gap("INVALID_LOCATION")
		return 0
	}
	i, err := n.Int64()
	if err != nil || i < 0 || i > 2147483647 {
		p.gap("INVALID_LOCATION")
		return 0
	}
	return int(i)
}
func (p *parsed) strings(m map[string]any, k string) []string {
	var out []string
	for _, v := range p.array(m, k, false) {
		s, ok := v.(string)
		if !ok || len(s) > 8192 {
			p.gap("INVALID_ITEM")
			continue
		}
		if len(out) >= maxItems {
			p.gap("RESULT_LIMIT")
			break
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

func parseNative(id string, data []byte) parsed {
	p := parsed{Status: "PARSED"}
	switch id {
	case "syft", "grype", "osv-scanner", "trivy", "gitleaks", "opengrep", "zizmor", "scancode", "reuse":
	default:
		p.Status = "UNSUPPORTED_FORMAT"
		return p
	}
	v, err := decodeJSON(data)
	if err != nil {
		p.Status = "MALFORMED_OUTPUT"
		return p
	}
	m := obj(v)
	if id == "gitleaks" || id == "zizmor" {
		a, ok := v.([]any)
		if !ok {
			p.Status = "UNSUPPORTED_FORMAT"
			return p
		}
		p.rows(a, func(x map[string]any) {
			if id == "gitleaks" {
				if !p.require(x, "RuleID", "File") {
					return
				}
				p.add(nativeItem{Category: "secret", Rule: str(x, "RuleID"), Path: str(x, "File"), Line: p.line(x, "StartLine"), ReviewReason: "SECRET_VALIDATION_REQUIRED"})
			} else {
				if !p.require(x, "ident") {
					return
				}
				d := obj(x["determinations"])
				a := p.array(x, "locations", true)
				path := ""
				for _, l := range a {
					local := obj(obj(obj(obj(l)["symbolic"])["key"])["Local"])
					if path == "" {
						path = str(local, "verbatim_path")
					}
				}
				if path == "" {
					p.gap("MISSING_LOCATION")
				}
				p.add(nativeItem{Category: "configuration", Rule: str(x, "ident"), Severity: severity(str(d, "severity")), NativeSeverity: str(d, "severity"), Path: path})
			}
		})
		return p
	}
	if m == nil {
		p.Status = "UNSUPPORTED_FORMAT"
		return p
	}
	for _, k := range []string{"error", "errors", "incomplete"} {
		if present(m[k]) {
			p.gap("SCANNER_REPORTED_INCOMPLETE")
		}
	}
	if s := strings.ToUpper(str(m, "status")); s == "ERROR" || s == "FAILED" || s == "PARTIAL" {
		p.gap("SCANNER_REPORTED_INCOMPLETE")
	}
	switch id {
	case "syft":
		used, ok := obj(obj(obj(m["descriptor"])["configuration"])["catalogers"])["used"].([]any)
		if ok && len(used) <= maxItems {
			valid, goCatalogers := true, 0
			for _, value := range used {
				name, isString := value.(string)
				valid = valid && isString
				if name == "go-module-file-cataloger" {
					goCatalogers++
				}
			}
			p.GoModuleFileCatalogerUsed = valid && goCatalogers == 1
		}
		version := str(obj(m["schema"]), "version")
		if version == "" {
			p.gap("MISSING_SCHEMA_VERSION")
		} else if version != "16.1.3" && version != "16.1.10" {
			// Exact reviewed schemas only. Syft 1.51.1 emits 16.1.10;
			// historical 16.1.3 evidence remains readable without admitting
			// an unreviewed later version as complete inventory.
			p.Status, p.Reasons = "UNSUPPORTED_FORMAT", []string{"UNSUPPORTED_NATIVE_SCHEMA"}
			return p
		}
		p.rows(p.array(m, "artifacts", true), func(x map[string]any) {
			if p.require(x, "name") {
				p.add(nativeItem{Category: "inventory", Component: str(x, "name"), ComponentVersion: str(x, "version"), PURL: str(x, "purl"), ComponentType: str(x, "type")})
			}
		})
		if present(obj(obj(m["descriptor"])["configuration"])["notes"]) {
			p.gap("SCANNER_REPORTED_INCOMPLETE")
		}
	case "grype":
		p.rows(p.array(m, "matches", true), func(x map[string]any) {
			v, a := obj(x["vulnerability"]), obj(x["artifact"])
			if !p.require(v, "id") || !p.require(a, "name") {
				return
			}
			path := ""
			for _, l := range p.array(a, "locations", false) {
				if path == "" {
					path = str(obj(l), "path")
				}
			}
			p.add(nativeItem{Category: "vulnerability", Rule: str(v, "id"), Severity: severity(str(v, "severity")), NativeSeverity: str(v, "severity"), Component: str(a, "name"), ComponentVersion: str(a, "version"), PURL: str(a, "purl"), Path: path, FixedVersions: p.strings(obj(v["fix"]), "versions")})
		})
		if present(m["ignoredMatches"]) {
			p.gap("SCANNER_OMITTED_ITEMS")
		}
	case "osv-scanner":
		p.rows(p.array(m, "results", true), func(r map[string]any) {
			path := str(obj(r["source"]), "path")
			p.rows(p.array(r, "packages", true), func(x map[string]any) {
				a := obj(x["package"])
				if !p.require(a, "name") {
					return
				}
				p.rows(p.array(x, "vulnerabilities", true), func(v map[string]any) {
					if !p.require(v, "id") {
						return
					}
					s := str(obj(v["database_specific"]), "severity")
					p.add(nativeItem{Category: "vulnerability", Rule: str(v, "id"), Severity: severity(s), NativeSeverity: s, Component: str(a, "name"), ComponentVersion: str(a, "version"), Path: path})
				})
			})
		})
	case "trivy":
		if m["SchemaVersion"] != json.Number("2") {
			p.gap("UNSUPPORTED_SCHEMA_VERSION")
		}
		// Trivy v0.74.0 serializes an empty Results slice with omitempty.
		// An absent field is valid, but an explicitly null or wrong-typed field
		// remains incomplete rather than being silently treated as empty.
		var results []any
		if _, exists := m["Results"]; exists {
			results = p.array(m, "Results", true)
		}
		p.rows(results, func(r map[string]any) {
			if !p.require(r, "Target") {
				return
			}
			if str(r, "Class") != "lang-pkgs" && str(r, "Class") != "os-pkgs" {
				p.gap("UNSUPPORTED_RESULT_KIND")
			}
			p.rows(p.array(r, "Vulnerabilities", false), func(v map[string]any) {
				if !p.require(v, "VulnerabilityID", "PkgName") {
					return
				}
				var fixes []string
				if s := str(v, "FixedVersion"); s != "" {
					fixes = []string{s}
				}
				p.add(nativeItem{Category: "vulnerability", Rule: str(v, "VulnerabilityID"), Severity: severity(str(v, "Severity")), NativeSeverity: str(v, "Severity"), Component: str(v, "PkgName"), ComponentVersion: str(v, "InstalledVersion"), Path: str(r, "Target"), FixedVersions: fixes})
			})
			for _, key := range []string{"Misconfigurations", "Secrets", "Licenses"} {
				if present(r[key]) {
					p.gap("UNSUPPORTED_RESULT_KIND")
				}
			}
		})
	case "opengrep":
		p.rows(p.array(m, "results", true), func(x map[string]any) {
			if !p.require(x, "check_id", "path") {
				return
			}
			extra := obj(x["extra"])
			p.add(nativeItem{Category: "sast", Rule: str(x, "check_id"), Path: str(x, "path"), Line: p.line(obj(x["start"]), "line"), Severity: severity(str(extra, "severity")), NativeSeverity: str(extra, "severity")})
		})
		if present(obj(m["paths"])["skipped"]) {
			p.gap("SCANNER_OMITTED_ITEMS")
		}
	case "scancode":
		p.scanCode(m)
	case "reuse":
		if str(m, "lint_version") != "1.0" {
			p.gap("UNSUPPORTED_SCHEMA_VERSION")
		}
		summary := obj(m["summary"])
		compliant, ok := summary["compliant"].(bool)
		if !ok {
			p.gap("MISSING_RESULT_FIELD")
		}
		files := p.array(m, "files", true)
		if _, exists := summary["files_total"]; !exists {
			p.gap("MISSING_RESULT_FIELD")
		} else if p.line(summary, "files_total") != len(files) {
			p.gap("CONTRADICTORY_RESULT")
		}
		p.rows(files, func(x map[string]any) {
			if !p.require(x, "path") {
				return
			}
			p.rows(p.array(x, "spdx_expressions", true), func(e map[string]any) {
				if !p.require(e, "value") {
					return
				}
				reason := ""
				if valid, ok := e["is_valid"].(bool); !ok || !valid {
					reason = "INVALID_LICENSE_EXPRESSION"
				}
				p.add(nativeItem{Category: "license", Rule: "observed-license", Path: str(x, "path"), Expression: str(e, "value"), ReviewReason: reason})
			})
		})
		noncompliant := obj(m["non_compliant"])
		if noncompliant == nil {
			p.gap("MISSING_RESULT_FIELD")
		}
		keys := make([]string, 0, len(noncompliant))
		for key := range noncompliant {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		issues := 0
		for _, key := range keys {
			for _, name := range p.strings(noncompliant, key) {
				issues++
				p.add(nativeItem{Category: "license", Rule: key, Component: name, ReviewReason: "REUSE_COMPLIANCE_REVIEW"})
				if key == "read_errors" {
					p.gap("SCANNER_REPORTED_INCOMPLETE")
				}
			}
		}
		if !compliant && issues == 0 {
			p.gap("MISSING_COMPLIANCE_DETAILS")
		}
		if compliant && issues > 0 {
			p.gap("CONTRADICTORY_RESULT")
		}
	}
	sort.Strings(p.Reasons)
	return p
}
