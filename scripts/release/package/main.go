// This helper has no external dependencies. It writes deterministic archives and verifies
// their exact allowlist without extracting or executing their contents.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

var adapters = []string{"gitleaks", "grype", "opengrep", "osv-scanner", "reuse", "sbomqs", "scancode", "syft", "trivy", "zizmor"}

type metadata struct {
	Version          string            `json:"version"`
	Revision         string            `json:"revision"`
	SourceState      string            `json:"source_state"`
	SourceTreeSHA256 string            `json:"source_tree_sha256"`
	SandboxSHA256    string            `json:"sandbox_sha256"`
	PaoSHA256        map[string]string `json:"pao_sha256"`
	ArchivesSHA256   map[string]string `json:"archives_sha256,omitempty"`
	GoVersion        string            `json:"go_version"`
	AsOf             string            `json:"as_of"`
}

// Public packages expose only the identity needed to select a compatible release.
// Build, source, and review evidence remains in the external private metadata.
type publicVersion struct {
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

func allowed(platform string) []string {
	names := []string{cliName(platform), "pao-sandbox-linux-amd64", "audit.json", "toolchain.catalog.json", "docker-provider.json", "START_HERE.uk.md", "LICENSE", "NOTICE", "licenses/GO-LICENSE.txt", "VERSION.json", "PACKAGE-CONTENTS.json"}
	for _, id := range adapters {
		names = append(names, "adapters/"+id+"/manifest.json")
	}
	sort.Strings(names)
	return names
}

func main() {
	mode := flag.String("mode", "verify", "pack or verify")
	path := flag.String("path", "", "archive path")
	stage := flag.String("stage", "", "allowlisted package directory")
	platform := flag.String("platform", "", "windows or linux")
	version := flag.String("version", "", "expected package version")
	metadataPath := flag.String("metadata", "", "private external build metadata (required for pack)")
	flag.Parse()
	if (*platform != "windows" && *platform != "linux") || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`).MatchString(*version) {
		fail(errors.New("invalid platform or version"))
	}
	var err error
	if *mode == "pack" {
		err = pack(*stage, *path, *platform, *version, *metadataPath)
	} else if *mode == "verify" {
		err = verifyWithMetadata(*path, *platform, *version, *metadataPath)
	} else {
		err = errors.New("unknown mode")
	}
	if err != nil {
		fail(err)
	}
	fmt.Println("PACKAGE_COMPOSITION_VERIFIED")
}
func fail(err error)            { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func cliName(platform string) string {
	if platform == "windows" {
		return "pao.exe"
	}
	return "pao"
}

func validate(files map[string][]byte, platform, version string) error {
	names := allowed(platform)
	if len(files) != len(names) {
		return errors.New("archive must contain exactly the allowlisted files")
	}
	for _, name := range names {
		if len(files[name]) == 0 {
			return fmt.Errorf("missing/empty allowed file: %s", name)
		}
	}
	var identity publicVersion
	if err := strictjson.Decode(files["VERSION.json"], &identity, 16384); err != nil {
		return err
	}
	if identity != (publicVersion{Version: version, Platform: platform, Architecture: "amd64"}) {
		return errors.New("invalid or inconsistent public version identity")
	}
	var sums map[string]string
	if err := strictjson.Decode(files["PACKAGE-CONTENTS.json"], &sums, 65536); err != nil {
		return err
	}
	if len(sums) != len(names)-1 {
		return errors.New("invalid content manifest inventory")
	}
	for _, name := range names {
		if name != "PACKAGE-CONTENTS.json" && sums[name] != digest(files[name]) {
			return fmt.Errorf("package content digest mismatch: %s", name)
		}
	}
	for _, id := range adapters {
		var manifest struct {
			ID         string `json:"id"`
			APIVersion string `json:"api_version"`
		}
		if err := json.Unmarshal(files["adapters/"+id+"/manifest.json"], &manifest); err != nil || manifest.ID != id || manifest.APIVersion != "pao.dev/adapter/v1alpha2" {
			return fmt.Errorf("invalid adapter manifest: %s", id)
		}
	}
	if err := validateBlankTemplates(files); err != nil {
		return err
	}
	return nil
}

type blankCatalog struct {
	APIVersion string   `json:"api_version"`
	Owner      string   `json:"owner"`
	ApprovedAt string   `json:"approved_at"`
	ExpiresAt  string   `json:"expires_at"`
	Tools      []string `json:"tools"`
}
type blankApproval struct {
	ID             string `json:"id"`
	Owner          string `json:"owner"`
	EvidenceDigest string `json:"evidence_digest"`
	ExpiresAt      string `json:"expires_at"`
}
type blankProvider struct {
	APIVersion      string        `json:"api_version"`
	DockerPath      string        `json:"docker_path"`
	DockerSHA256    string        `json:"docker_sha256"`
	RuntimeImage    string        `json:"runtime_image"`
	RuntimeApproval blankApproval `json:"runtime_approval"`
}

func blankTemplates() map[string]any {
	return map[string]any{
		"audit.json":             map[string]string{"version": "pao.dev/local-audit-config/v2", "target": "REPLACE_WITH_ABSOLUTE_TARGET_DIRECTORY", "evidence_base": "REPLACE_WITH_SEPARATE_PRIVATE_EVIDENCE_DIRECTORY", "report_base": "REPLACE_WITH_SEPARATE_REPORT_DIRECTORY", "toolchain_root": "REPLACE_WITH_PRIVATE_INSTALLED_TOOLS_DIRECTORY", "manifest_root": "REPLACE_WITH_PACKAGE_ADAPTERS_DIRECTORY", "toolchain_catalog": "REPLACE_WITH_ABSOLUTE_PRIVATE_CATALOG_FILE", "docker_base_provider": "REPLACE_WITH_ABSOLUTE_PRIVATE_PROVIDER_FILE", "docker_scancode_provider": "", "rule_pack_root": ""},
		"toolchain.catalog.json": blankCatalog{"pao.dev/toolchain-catalog/v1", "UNAPPROVED", "1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z", []string{}},
		"docker-provider.json":   blankProvider{"pao.dev/docker-provider/v1alpha1", "REPLACE_WITH_ABSOLUTE_DOCKER_CLI_PATH", "REPLACE_WITH_SHA256_PREFIX_AND_64_HEX_DIGITS", "REPLACE_WITH_APPROVED_LOCAL_IMAGE_SHA256_ID", blankApproval{"UNAPPROVED", "UNAPPROVED", "REPLACE_WITH_REVIEW_EVIDENCE_SHA256", "1970-01-01T00:00:00Z"}},
	}
}

func validateBlankTemplates(files map[string][]byte) error {
	for name, expected := range blankTemplates() {
		actual := reflect.New(reflect.TypeOf(expected))
		if err := strictjson.Decode(files[name], actual.Interface(), 16384); err != nil {
			return fmt.Errorf("invalid public template %s: %w", name, err)
		}
		if !reflect.DeepEqual(actual.Elem().Interface(), expected) {
			return fmt.Errorf("public template must contain only blank unapproved placeholders: %s", name)
		}
	}
	return nil
}

func readMetadata(path, version string) (metadata, error) {
	var m metadata
	if path == "" {
		return m, errors.New("private external build metadata is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return m, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16384 {
		return m, errors.New("invalid private build metadata file")
	}
	file, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil {
		return m, err
	}
	if err := strictjson.Decode(data, &m, 16384); err != nil {
		return m, err
	}
	if m.Version != version || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.Revision) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.SourceTreeSHA256) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.SandboxSHA256) || (m.SourceState != "clean" && m.SourceState != "modified") || !regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m.GoVersion) {
		return m, errors.New("invalid or inconsistent private build identity")
	}
	if _, err := time.Parse(time.RFC3339, m.AsOf); err != nil {
		return m, err
	}
	if len(m.PaoSHA256) != 2 {
		return m, errors.New("private build metadata requires both platform CLI identities")
	}
	for _, hashes := range []map[string]string{m.PaoSHA256, m.ArchivesSHA256} {
		for platform, hash := range hashes {
			if (platform != "windows" && platform != "linux") || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) {
				return m, errors.New("invalid private platform digest")
			}
		}
	}
	return m, nil
}

func validatePrivateBinaries(files map[string][]byte, platform string, m metadata) error {
	if m.SandboxSHA256 != digest(files["pao-sandbox-linux-amd64"]) {
		return errors.New("bundled sandbox identity mismatch")
	}
	if m.PaoSHA256[platform] != digest(files[cliName(platform)]) {
		return errors.New("bundled CLI identity mismatch")
	}
	return nil
}

func pack(stage, path, platform, version, metadataPath string) error {
	m, err := readMetadata(metadataPath, version)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	names := allowed(platform)
	allow := map[string]bool{}
	for _, name := range names {
		allow[name] = true
	}
	if err := filepath.WalkDir(stage, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("linked package input")
		}
		if entry.IsDir() {
			return nil
		}
		name, err := filepath.Rel(stage, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if !allow[name] || name == "PACKAGE-CONTENTS.json" || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected package input: %s", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[name] = data
		return nil
	}); err != nil {
		return err
	}
	sums := map[string]string{}
	for name, data := range files {
		sums[name] = digest(data)
	}
	manifest, err := json.MarshalIndent(sums, "", "  ")
	if err != nil {
		return err
	}
	files["PACKAGE-CONTENTS.json"] = append(manifest, '\n')
	if err := validate(files, platform, version); err != nil {
		return err
	}
	if err := validatePrivateBinaries(files, platform, m); err != nil {
		return err
	}
	asOf, _ := time.Parse(time.RFC3339, m.AsOf)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	if platform == "windows" {
		writer := zip.NewWriter(out)
		for _, name := range names {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetModTime(asOf)
			header.SetMode(0644)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			if _, err := entry.Write(files[name]); err != nil {
				return err
			}
		}
		if err := writer.Close(); err != nil {
			return err
		}
	} else {
		compressed := gzip.NewWriter(out)
		writer := tar.NewWriter(compressed)
		for _, name := range names {
			mode := int64(0644)
			if name == "pao" || name == "pao-sandbox-linux-amd64" {
				mode = 0755
			}
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(files[name])), ModTime: asOf, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
				return err
			}
			if _, err := writer.Write(files[name]); err != nil {
				return err
			}
		}
		if err := writer.Close(); err != nil {
			return err
		}
		if err := compressed.Close(); err != nil {
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	// The completed archive digest is recorded by the caller after packing both
	// platforms. Private verification requires that final binding; packing cannot.
	if m.ArchivesSHA256[platform] != "" {
		return verifyWithMetadata(path, platform, version, metadataPath)
	}
	return verify(path, platform, version)
}

func verify(path, platform, version string) error {
	return verifyWithMetadata(path, platform, version, "")
}
func verifyWithMetadata(path, platform, version, metadataPath string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<20 {
		return errors.New("invalid archive file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return errors.New("archive changed before reading")
	}
	// Parse and hash one bounded byte snapshot so metadata cannot bind a separate
	// read of an archive that changed during verification.
	archiveData, err := io.ReadAll(io.LimitReader(file, (128<<20)+1))
	if err != nil {
		return err
	}
	if len(archiveData) > 128<<20 {
		return errors.New("archive exceeds size limit")
	}
	files := map[string][]byte{}
	allow := map[string]bool{}
	for _, name := range allowed(platform) {
		allow[name] = true
	}
	var total int64
	read := func(name string, r io.Reader, size int64) error {
		if !allow[name] || files[name] != nil || size <= 0 || size > 64<<20 {
			return fmt.Errorf("unexpected, duplicate or oversized archive entry: %s", name)
		}
		total += size
		if total > 128<<20 {
			return errors.New("unpacked archive exceeds size limit")
		}
		data, err := io.ReadAll(io.LimitReader(r, size+1))
		if err != nil {
			return err
		}
		if int64(len(data)) != size {
			return errors.New("archive size mismatch")
		}
		files[name] = data
		return nil
	}
	if platform == "windows" {
		reader, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
		if err != nil {
			return err
		}
		for _, entry := range reader.File {
			if !entry.Mode().IsRegular() {
				return errors.New("non-regular ZIP entry")
			}
			r, err := entry.Open()
			if err != nil {
				return err
			}
			err = read(entry.Name, r, int64(entry.UncompressedSize64))
			r.Close()
			if err != nil {
				return err
			}
		}
	} else {
		compressed, err := gzip.NewReader(bytes.NewReader(archiveData))
		if err != nil {
			return err
		}
		defer compressed.Close()
		reader := tar.NewReader(compressed)
		for {
			entry, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if entry.Typeflag != tar.TypeReg || entry.Linkname != "" || len(entry.PAXRecords) != 0 {
				return errors.New("non-regular tar entry")
			}
			if (entry.Name == "pao" || entry.Name == "pao-sandbox-linux-amd64") && entry.Mode != 0755 {
				return errors.New("Linux binary lacks exact executable mode")
			}
			if err := read(entry.Name, reader, entry.Size); err != nil {
				return err
			}
		}
		// Complete decompression to validate gzip checksum and reject hidden payloads.
		remaining, err := io.ReadAll(io.LimitReader(compressed, 1025))
		if err != nil {
			return err
		}
		if len(remaining) > 1024 || len(bytes.Trim(remaining, "\x00")) != 0 {
			return errors.New("unexpected tar trailing data")
		}
	}
	if err := validate(files, platform, version); err != nil {
		return err
	}
	if metadataPath != "" {
		m, err := readMetadata(metadataPath, version)
		if err != nil {
			return err
		}
		if err := validatePrivateBinaries(files, platform, m); err != nil {
			return err
		}
		if m.ArchivesSHA256[platform] == "" {
			return errors.New("private build metadata lacks selected platform archive identity")
		}
		if m.ArchivesSHA256[platform] != digest(archiveData) {
			return errors.New("archive identity mismatch")
		}
	}
	// Filenames are part of the release identity, not merely descriptive labels.
	ext := ".tar.gz"
	if platform == "windows" {
		ext = ".zip"
	}
	if filepath.Base(path) != "pao-"+version+"-"+platform+"-amd64"+ext {
		return errors.New("archive filename/version mismatch")
	}
	return nil
}
