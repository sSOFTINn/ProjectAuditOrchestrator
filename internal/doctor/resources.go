package doctor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
)

// streamBounded checks identity around bounded streaming; it creates no files.
// As with the runtime's input inspection, the owner and privileged processes
// remain trusted. Execution independently freezes and revalidates these inputs.
func streamBounded(ctx context.Context, path string, limit int64, writer io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := auditconfig.CheckPath(path, false); err != nil {
		return 0, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return 0, errors.New("file exceeds inspection limits or is not regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return 0, errors.New("file changed before inspection")
	}
	var count int64
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		remaining := limit - count + 1
		if remaining < int64(len(buffer)) {
			buffer = buffer[:remaining]
		}
		n, readErr := f.Read(buffer)
		count += int64(n)
		if count > limit || count > opened.Size() {
			return count, errors.New("file grew beyond inspection limit")
		}
		if n > 0 {
			if _, err := writer.Write(buffer[:n]); err != nil {
				return count, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return count, readErr
		}
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || count != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || !os.SameFile(current, opened) {
		return count, errors.New("file changed during inspection")
	}
	if err := auditconfig.CheckPath(path, false); err != nil {
		return count, err
	}
	return count, nil
}

func readBounded(ctx context.Context, path string, limit int64) ([]byte, error) {
	var content bytes.Buffer
	_, err := streamBounded(ctx, path, limit, &content)
	if err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}

func verifyFile(ctx context.Context, path, expected string, limit int64) error {
	if !cleanDigest(expected) {
		return errors.New("missing or invalid expected SHA-256")
	}
	h := sha256.New()
	if _, err := streamBounded(ctx, path, limit, h); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("SHA-256 mismatch")
	}
	return nil
}

type capsuleEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type capsuleManifest struct {
	APIVersion      string         `json:"api_version,omitempty"`
	Schema          string         `json:"schema,omitempty"`
	AdapterID       string         `json:"adapter_id,omitempty"`
	Tool            string         `json:"tool,omitempty"`
	Kind            string         `json:"kind,omitempty"`
	Files           []capsuleEntry `json:"files"`
	SupportingFiles []capsuleEntry `json:"supporting_files,omitempty"`
	// Database provenance is bound by the approved manifest hash. Readiness
	// validates the actual inventory; it does not re-resolve public sources.
	BuiltAt       time.Time      `json:"built_at,omitempty"`
	Source        databaseSource `json:"source,omitempty"`
	ArchiveSHA256 string         `json:"archive_sha256,omitempty"`
}

// Mirrors the versioned provenance emitted by setup without coupling a
// read-only inspection package to the online preparation command.
type databaseSource struct {
	Version        string    `json:"version"`
	Tool           string    `json:"tool"`
	URL            string    `json:"url"`
	SHA256         string    `json:"sha256,omitempty"`
	Bytes          int64     `json:"bytes"`
	Filename       string    `json:"filename"`
	RemoteFilename string    `json:"remote_filename,omitempty"`
	Format         string    `json:"format"`
	At             time.Time `json:"at"`
	ResolvedAt     time.Time `json:"resolved_at"`
	MetadataSHA256 string    `json:"metadata_sha256"`
	Generation     string    `json:"generation,omitempty"`
	MD5            string    `json:"md5_base64,omitempty"`
	CRC32C         string    `json:"crc32c_base64,omitempty"`
}

func verifyCapsule(ctx context.Context, root, kind, expected, id string) error {
	if !cleanDigest(expected) {
		return errors.New("invalid capsule digest")
	}
	name := ""
	switch kind {
	case "database":
		name = "metadata.json"
	case "state":
		name = "pao-state-manifest.json"
	case "rules":
		name = "pao-input-manifest.json"
	default:
		return errors.New("unknown capsule type")
	}
	raw, err := readBounded(ctx, filepath.Join(root, name), runner.FrozenMaxManifestBytes)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != expected {
		return errors.New("capsule manifest changed")
	}
	var manifest capsuleManifest
	if err := strictjson.Decode(raw, &manifest, int(runner.FrozenMaxManifestBytes)); err != nil {
		return err
	}
	switch kind {
	case "database":
		if manifest.Schema != "pao.dev/toolchain-database-metadata/v1" || manifest.Tool != id {
			return errors.New("database identity mismatch")
		}
	case "state":
		if manifest.APIVersion != "pao.dev/prepared-state/v1alpha1" || manifest.AdapterID != id {
			return errors.New("state identity mismatch")
		}
	case "rules":
		if manifest.APIVersion != "pao.dev/input-capsule/v1alpha1" || manifest.AdapterID != id || manifest.Kind != "rule-pack" {
			return errors.New("rule-pack identity mismatch")
		}
	}
	if len(manifest.Files) == 0 || len(manifest.Files)+len(manifest.SupportingFiles) >= runner.FrozenMaxEntries {
		return errors.New("capsule inventory exceeds limits")
	}
	entries := append(manifest.Files, manifest.SupportingFiles...)
	want := make(map[string]string, len(entries))
	caseNames := map[string]bool{}
	for _, entry := range entries {
		if !toolchain.SafeRelative(entry.Path) || entry.Path == name || !cleanDigest("sha256:"+entry.SHA256) {
			return errors.New("unsafe capsule path or digest")
		}
		key := entry.Path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if caseNames[key] {
			return errors.New("duplicate capsule path")
		}
		caseNames[key] = true
		want[entry.Path] = entry.SHA256
	}
	seen := map[string]bool{}
	var count int
	var total int64
	var walk func(string) error
	walk = func(directory string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := auditconfig.CheckPath(directory, false); err != nil {
			return err
		}
		before, err := os.Lstat(directory)
		if err != nil || !before.IsDir() {
			return errors.New("capsule directory is not regular")
		}
		dir, err := os.Open(directory)
		if err != nil {
			return err
		}
		defer dir.Close()
		opened, err := dir.Stat()
		if err != nil || !os.SameFile(before, opened) {
			return errors.New("capsule directory changed")
		}
		for {
			batch, readErr := dir.ReadDir(128)
			for _, entry := range batch {
				count++
				if count > runner.FrozenMaxEntries {
					return errors.New("capsule entry budget exceeded")
				}
				path := filepath.Join(directory, entry.Name())
				if err := auditconfig.CheckPath(path, false); err != nil {
					return err
				}
				if entry.IsDir() {
					if err := walk(path); err != nil {
						return err
					}
					continue
				}
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				rel = filepath.ToSlash(rel)
				if rel == name {
					continue
				}
				digest, ok := want[rel]
				if !ok || seen[rel] {
					return errors.New("capsule file set differs from manifest")
				}
				h := sha256.New()
				limit := min(runner.FrozenMaxFileBytes, runner.FrozenMaxTotalBytes-total)
				if limit < 0 {
					return errors.New("capsule byte budget exceeded")
				}
				n, err := streamBounded(ctx, path, limit, h)
				total += n
				if err != nil {
					return err
				}
				if hex.EncodeToString(h.Sum(nil)) != digest {
					return errors.New("capsule content digest mismatch")
				}
				seen[rel] = true
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return err
	}
	if len(seen) != len(want) {
		return errors.New("capsule has missing files")
	}
	return ctx.Err()
}
