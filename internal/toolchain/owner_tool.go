package toolchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	pathpkg "path"
	"strings"
	"time"
	"unicode/utf8"
)

const OwnerToolRecordVersion = "pao.dev/owner-tool-record/v1"
const maxOwnerToolRecordBytes = 16 << 10

// OwnerApprovedTool is a data-only local-tool registration. Its binary remains
// outside the repository and is verified again immediately before launch.
type OwnerApprovedTool struct {
	Record         Record
	Binary         string
	Owner          string
	ApprovedAt     time.Time
	MetadataDigest string
}

// LoadOwnerApprovedTool accepts one flat, duplicate-free JSON record. Approval
// expires after 90 days so an old local binary cannot silently remain trusted.
func LoadOwnerApprovedTool(file, expectedID string, now time.Time) (OwnerApprovedTool, error) {
	var result OwnerApprovedTool
	info, err := os.Lstat(file)
	if err != nil {
		return result, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return result, errors.New("owner tool record must be a regular non-link file")
	}
	if info.Size() > maxOwnerToolRecordBytes {
		return result, errors.New("owner tool record exceeds the safety limit")
	}
	f, err := os.Open(file)
	if err != nil {
		return result, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxOwnerToolRecordBytes+1))
	if err != nil {
		return result, err
	}
	if len(raw) > maxOwnerToolRecordBytes {
		return result, errors.New("owner tool record exceeds the safety limit")
	}
	values, err := decodeOwnerToolRecord(raw)
	if err != nil {
		return result, err
	}
	required := []string{"api_version", "id", "version", "sha256", "source_license", "redistribution", "binary", "platform", "owner", "approved_at"}
	for _, key := range required {
		if values[key] == "" {
			return result, errors.New("owner tool record is missing a required field")
		}
	}
	if values["api_version"] != OwnerToolRecordVersion || values["id"] != expectedID || values["platform"] != "linux-amd64" || !isSHA256(values["sha256"]) {
		return result, errors.New("owner tool record has an unsupported identity")
	}
	clean := pathpkg.Clean(values["binary"])
	if clean == "." || clean == ".." || clean != values["binary"] || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.ContainsAny(values["binary"], "\\:") {
		return result, errors.New("owner tool binary must be a safe relative POSIX path")
	}
	approvedAt, err := time.Parse(time.RFC3339, values["approved_at"])
	if err != nil || approvedAt.After(now) || now.Sub(approvedAt) > 90*24*time.Hour {
		return result, errors.New("owner tool approval is missing, future-dated or stale")
	}
	sum := sha256.Sum256(raw)
	result = OwnerApprovedTool{Record: Record{ID: expectedID, Version: values["version"], SHA256: values["sha256"], SourceLicense: values["source_license"], Redistribution: values["redistribution"]}, Binary: values["binary"], Owner: values["owner"], ApprovedAt: approvedAt.UTC(), MetadataDigest: "sha256:" + hex.EncodeToString(sum[:])}
	return result, nil
}

func decodeOwnerToolRecord(raw []byte) (map[string]string, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("owner tool record is not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("owner tool record must be one object")
	}
	allowed := map[string]bool{"api_version": true, "id": true, "version": true, "sha256": true, "source_license": true, "redistribution": true, "binary": true, "platform": true, "owner": true, "approved_at": true}
	values := map[string]string{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || values[key] != "" {
			return nil, errors.New("owner tool record has an unknown or duplicate field")
		}
		var value string
		if err := d.Decode(&value); err != nil || value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return nil, errors.New("owner tool record values must be nonempty strings")
		}
		values[key] = value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("owner tool record is not closed")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("owner tool record has trailing content")
	}
	return values, nil
}
