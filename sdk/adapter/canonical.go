package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// CanonicalJSON removes ordering as a source of permission drift before a manifest enters a plan lock.
func CanonicalJSON(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	copy := m
	copy.Capabilities = sorted(m.Capabilities)
	copy.SupportedPlatforms = sorted(m.SupportedPlatforms)
	copy.InputKinds = sorted(m.InputKinds)
	copy.OutputKinds = sorted(m.OutputKinds)
	copy.InputIndicators = sorted(m.InputIndicators)
	copy.CompatibleToolVersions = sorted(m.CompatibleToolVersions)
	copy.FixedArguments = append([]string(nil), m.FixedArguments...)
	copy.AllowedEnvironment = sorted(m.AllowedEnvironment)
	copy.SuccessExitCodes = append([]int(nil), m.SuccessExitCodes...)
	sort.Ints(copy.SuccessExitCodes)
	copy.RequiredSandbox = sorted(m.RequiredSandbox)
	copy.PrerequisiteKinds = sorted(m.PrerequisiteKinds)
	copy.FixtureCases = sorted(m.FixtureCases)
	copy.Limitations = sorted(m.Limitations)
	return json.Marshal(copy)
}

func Digest(m Manifest) (string, error) {
	encoded, err := CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sorted(values []string) []string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	return copy
}
