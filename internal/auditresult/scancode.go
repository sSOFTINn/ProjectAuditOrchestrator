package auditresult

import "strconv"

// Package strings remain private assertions. JSON pointers distinguish repeated
// file-level/assembled records without guessing cross-record equivalence.
func (p *parsed) optionalString(m map[string]any, key string) string {
	v, exists := m[key]
	if !exists || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		p.gap("INVALID_ITEM")
	}
	return s
}

func (p *parsed) optionalBool(m map[string]any, key string) *bool {
	v, exists := m[key]
	if !exists || v == nil {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		p.gap("INVALID_ITEM")
		return nil
	}
	return &b
}

func (p *parsed) indexed(a []any, pointer string, f func(map[string]any, string)) {
	for index, v := range a {
		if len(p.Items) >= maxItems {
			p.gap("RESULT_LIMIT")
			return
		}
		m := obj(v)
		if m == nil {
			p.gap("INVALID_ITEM")
			continue
		}
		f(m, pointer+"/"+strconv.Itoa(index))
	}
}

func (p *parsed) scanCode(m map[string]any) {
	headers := p.array(m, "headers", true)
	if len(headers) == 0 {
		p.gap("MISSING_RESULT_FIELD")
	}
	p.rows(headers, func(h map[string]any) {
		if str(h, "tool_name") != "scancode-toolkit" {
			p.gap("UNSUPPORTED_RESULT_KIND")
		}
		if v := p.optionalString(h, "output_format_version"); v != "" && v != "4.1.0" {
			p.gap("UNSUPPORTED_SCHEMA_VERSION")
		}
		if present(h["errors"]) || present(h["warnings"]) {
			p.gap("SCANNER_REPORTED_INCOMPLETE")
		}
	})
	p.indexed(p.array(m, "files", true), "/files", func(x map[string]any, pointer string) {
		if !p.require(x, "path", "type") {
			return
		}
		if present(x["scan_errors"]) {
			p.gap("SCANNER_REPORTED_INCOMPLETE")
		}
		path := str(x, "path")
		p.indexed(p.array(x, "package_data", false), pointer+"/package_data", func(pkg map[string]any, ptr string) { p.scanCodePackage(pkg, ptr, path, "scancode-package-data", 0) })
		if str(x, "type") == "directory" {
			return
		}
		if str(x, "type") != "file" {
			p.gap("UNSUPPORTED_RESULT_KIND")
			return
		}
		p.scanCodeLicense(nativeItem{Path: path}, x, "detected_license_expression_spdx", pointer)
	})
	p.indexed(p.array(m, "packages", false), "/packages", func(pkg map[string]any, ptr string) { p.scanCodePackage(pkg, ptr, "", "scancode-package", 0) })
	p.indexed(p.array(m, "dependencies", false), "/dependencies", func(dep map[string]any, ptr string) { p.scanCodeDependency(dep, ptr, "", 0) })
}

func (p *parsed) scanCodeLicense(base nativeItem, m map[string]any, key, pointer string) {
	base.Category, base.Rule, base.SourcePointer = "license", "observed-license", pointer+"/"+key
	if _, exists := m[key]; !exists {
		base.SourcePointer = pointer
	}
	base.Expression = p.optionalString(m, key)
	if base.Expression == "" {
		base.Rule = "missing-license-expression"
		base.ReviewReason = "MISSING_LICENSE_INFORMATION"
	}
	p.add(base)
}

func (p *parsed) scanCodePackage(m map[string]any, pointer, path, rule string, depth int) {
	if depth > 8 {
		p.gap("RESULT_LIMIT")
		return
	}
	if !p.require(m, "type", "name") {
		return
	}
	paths := p.strings(m, "datafile_paths")
	if path == "" && len(paths) > 0 {
		path = paths[0]
	}
	sources := p.strings(m, "datasource_ids")
	if s := p.optionalString(m, "datasource_id"); s != "" {
		sources = append(sources, s)
	}
	item := nativeItem{Category: "inventory", Rule: rule, SourcePointer: pointer, Path: path,
		Component: str(m, "name"), ComponentType: str(m, "type"), ComponentNamespace: p.optionalString(m, "namespace"),
		ComponentVersion: p.optionalString(m, "version"), PURL: p.optionalString(m, "purl"),
		PackageUID: p.optionalString(m, "package_uid"), DatafilePaths: paths, DatasourceIDs: sources}
	p.add(item)
	p.scanCodeLicense(item, m, "declared_license_expression_spdx", pointer)
	if present(m["other_license_expression_spdx"]) || present(m["other_license_expression"]) {
		p.scanCodeLicense(item, m, "other_license_expression_spdx", pointer)
	}
	p.indexed(p.array(m, "dependencies", false), pointer+"/dependencies", func(dep map[string]any, ptr string) { p.scanCodeDependency(dep, ptr, path, depth+1) })
}

func (p *parsed) scanCodeDependency(m map[string]any, pointer, path string, depth int) {
	if depth > 8 {
		p.gap("RESULT_LIMIT")
		return
	}
	if !p.require(m, "purl") {
		return
	}
	if s := p.optionalString(m, "datafile_path"); s != "" {
		path = s
	}
	p.add(nativeItem{Category: "inventory", Rule: "scancode-dependency", SourcePointer: pointer, Path: path, PURL: str(m, "purl"),
		ForPackageUID: p.optionalString(m, "for_package_uid"), DependencyUID: p.optionalString(m, "dependency_uid"),
		Requirement: p.optionalString(m, "extracted_requirement"), Scope: p.optionalString(m, "scope"),
		IsRuntime: p.optionalBool(m, "is_runtime"), IsOptional: p.optionalBool(m, "is_optional"), IsPinned: p.optionalBool(m, "is_pinned"), IsDirect: p.optionalBool(m, "is_direct")})
	if v := m["resolved_package"]; v != nil {
		resolved := obj(v)
		if resolved == nil {
			p.gap("INVALID_ITEM")
		} else if len(resolved) > 0 {
			p.scanCodePackage(resolved, pointer+"/resolved_package", path, "scancode-resolved-package", depth+1)
		}
	}
}
