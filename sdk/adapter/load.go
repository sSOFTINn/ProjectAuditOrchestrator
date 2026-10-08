package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

const maxManifestBytes int64 = 1 << 20

// LoadFile accepts one local static manifest only. It rejects links and oversized data so target
// content can never redirect or expand the trusted adapter declaration boundary.
func LoadFile(path string) (Manifest, error) {
	if path == "" || !filepath.IsAbs(path) {
		return Manifest{}, errors.New("absolute manifest path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return Manifest{}, errors.New("manifest must be a bounded real regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxManifestBytes {
		return Manifest{}, errors.New("manifest must be a bounded real regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := strictjson.Decode(raw, &manifest, int(maxManifestBytes)); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	// Presence is independent of the decoded zero value. In particular, omitted
	// writes_target/executes_target_code must never silently become a safety claim.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest fields: %w", err)
	}
	for _, name := range requiredManifestFields {
		if _, exists := fields[name]; !exists {
			return Manifest{}, fmt.Errorf("manifest is missing required field %q", name)
		}
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// These required fields belong to the versioned v1alpha2 wire contract; optional
// arrays may be omitted, but explicit null is rejected by strictjson.Decode.
var requiredManifestFields = []string{
	"api_version", "id", "display_name", "upstream", "capabilities", "supported_platforms",
	"input_kinds", "output_kinds", "source_license", "redistribution", "network",
	"writes_target", "executes_target_code", "timeout_seconds", "parser_schema", "fixed_arguments",
	"required_sandbox", "prerequisite_kinds", "fixture_cases", "max_output_bytes", "redaction_class",
}
