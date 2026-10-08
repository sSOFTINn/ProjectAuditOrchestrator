package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FixtureExpectation is a data-only assertion about a synthetic native output.
// The parser owns interpretation; this package only ensures a complete, explicit matrix exists.
type FixtureExpectation struct {
	Status       string `json:"status"`
	CoverageCode string `json:"coverage_code,omitempty"`
	MediaType    string `json:"media_type"`
}

func LoadFixtureMatrix(root string, manifest Manifest) (map[string]FixtureExpectation, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("absolute fixture root is required")
	}
	matrix := make(map[string]FixtureExpectation, len(manifest.FixtureCases))
	for _, name := range manifest.FixtureCases {
		path := filepath.Join(root, name+".expected.json")
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
			return nil, fmt.Errorf("fixture expectation unavailable: %s", name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var expectation FixtureExpectation
		if err := json.Unmarshal(raw, &expectation); err != nil || expectation.Status == "" || expectation.MediaType == "" {
			return nil, fmt.Errorf("invalid fixture expectation: %s", name)
		}
		matrix[name] = expectation
	}
	return matrix, nil
}

func SortedFixtureNames(matrix map[string]FixtureExpectation) []string {
	names := make([]string, 0, len(matrix))
	for name := range matrix {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
