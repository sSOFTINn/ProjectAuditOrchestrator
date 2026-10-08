package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDockerProviderConfigRejectsUnknownFieldsAndExpiredApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.json")
	dockerPath := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(dockerPath, []byte("synthetic docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("synthetic docker"))
	validConfig := DockerProviderConfig{
		APIVersion:   DockerProviderConfigVersion,
		DockerPath:   dockerPath,
		DockerSHA256: "sha256:" + hex.EncodeToString(sum[:]),
		RuntimeImage: fixtureImage,
		RuntimeApproval: RuntimeApproval{
			ID: "review", Owner: "security", EvidenceDigest: fixtureImage,
			ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	validBytes, err := json.Marshal(validConfig)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(validBytes)
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadDockerProviderConfig(path, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	if err != nil || config.Host().RuntimeImage != fixtureImage {
		t.Fatalf("valid provider config rejected: %#v %v", config, err)
	}
	for name, invalid := range map[string]string{
		"duplicate":        strings.Replace(valid, `"runtime_image":`, `"runtime_image":"`+fixtureImage+`","runtime_image":`, 1),
		"case-alias":       strings.Replace(valid, `"runtime_image":`, `"Runtime_Image":`, 1),
		"nested-duplicate": strings.Replace(valid, `"owner":`, `"owner":"other","owner":`, 1),
		"nested-alias":     strings.Replace(valid, `"owner":`, `"Owner":`, 1),
		"null-owner":       strings.Replace(valid, `"owner":"security"`, `"owner":null`, 1),
		"trailing-object":  valid + `{}`,
		"oversized":        strings.Repeat(" ", int(maxDockerConfigBytes)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDockerProviderConfig(path, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("ambiguous or unbounded provider config was accepted")
			}
		})
	}
	if err := os.WriteFile(path, validBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerPath, []byte("tampered docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerProviderConfig(path, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("tampered Docker CLI was accepted")
	}
	if err := os.WriteFile(dockerPath, []byte("synthetic docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(valid[:len(valid)-1]+`,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerProviderConfig(path, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("unknown config field was accepted")
	}
	validConfig.RuntimeApproval.ExpiresAt = time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	expiredBytes, err := json.Marshal(validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, expiredBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerProviderConfig(path, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired provider approval was accepted")
	}
}
