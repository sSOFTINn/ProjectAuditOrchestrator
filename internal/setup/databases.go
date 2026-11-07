package setup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" // GCS publishes MD5 and CRC32C, not SHA-256; both are checked.
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/runner"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/toolchain"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/zstd"
)

const databaseLockVersion = "pao.dev/database-download-lock/v1"
const databaseMetadataVersion = "pao.dev/toolchain-database-metadata/v1"
const databaseArchiveLimit int64 = 512 << 20
const databaseExpandedLimit int64 = 4 << 30
const grypeListingURL = "https://grype.anchore.io/databases/v6/latest.json"
const trivyManifestURL = "https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2"
const osvObjectURL = "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/Go%2Fall.zip"

// OSV-Scanner 2.5.1 delegates offline matching to its pinned osv-scalibr
// dependency. The matcher appends this namespace to the configured cache root.
const osvArchivePath = "osv-scalibr/Go/all.zip"

type databasePrepared struct {
	Path        string            `json:"path"`
	Digest      string            `json:"digest"`
	At          time.Time         `json:"at"`
	Environment map[string]string `json:"environment"`
}

// databaseLock is saved before downloading payload bytes. GCS lacks a public
// SHA-256, so its immutable generation, MD5 and CRC32C remain explicit; the
// locally computed SHA-256 is recorded in the resulting snapshot metadata.
type databaseLock struct {
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

type preparedDatabaseMetadata struct {
	Schema        string       `json:"schema"`
	Tool          string       `json:"tool"`
	Files         []fileDigest `json:"files"`
	BuiltAt       time.Time    `json:"built_at"`
	Source        databaseLock `json:"source"`
	ArchiveSHA256 string       `json:"archive_sha256"`
}

// prepareDatabases never accepts target data. The supplied hydrator runs the
// verified Grype binary in a network-denied preparation container. It receives
// one extracted read-only vulnerability.db file and a new, empty destination.
// Grype itself must hydrate indexes and emit import.json before we seal files.
func prepareDatabases(ctx context.Context, d *downloader, cache, toolsRoot string, hydrate func(context.Context, string, string) error) (map[string]databasePrepared, error) {
	if hydrate == nil {
		return nil, errors.New("verified offline Grype database hydrator is required")
	}
	if err := privateTree(cache); err != nil {
		return nil, err
	}
	if err := privateTree(toolsRoot); err != nil {
		return nil, err
	}
	result := map[string]databasePrepared{}
	for _, id := range []string{"grype", "trivy", "osv-scanner"} {
		prepared, err := prepareDatabase(ctx, d, cache, toolsRoot, id, hydrate)
		if err != nil {
			return result, fmt.Errorf("prepare %s database: %w", id, err)
		}
		result[id] = prepared
	}
	return result, nil
}

func prepareDatabase(ctx context.Context, d *downloader, cache, toolsRoot, id string, hydrate func(context.Context, string, string) error) (databasePrepared, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var zero databasePrepared
	lockPath := filepath.Join(cache, "database-"+id+"-lock.json")
	var lock databaseLock
	raw, err := readOptionalDatabaseFile(lockPath)
	if err == nil {
		if err := strictjson.Decode(raw, &lock, 1<<20); err != nil {
			return zero, err
		}
	} else if !os.IsNotExist(err) {
		return zero, err
	} else {
		lock, err = resolveDatabase(ctx, d, id)
		if err != nil {
			return zero, err
		}
		raw, err = json.MarshalIndent(lock, "", "  ")
		if err != nil {
			return zero, err
		}
		if err := validateDatabaseLock(lock, id, time.Now()); err != nil {
			return zero, err
		}
		if err := writeOnce(lockPath, raw); err != nil {
			return zero, err
		}
	}
	if err := validateDatabaseLock(lock, id, time.Now()); err != nil {
		return zero, err
	}
	// Completion paths are relative to this tools generation. Sharing them with
	// the download cache would make a new recipe resolve the old generation's
	// relative path beneath its own tools root. Only immutable sources and
	// archives are shared; each generation verifies and seals its own output.
	readyRoot := filepath.Join(toolsRoot, "database-preparation")
	if err := privateTree(readyRoot); err != nil {
		return zero, err
	}
	readyPath := filepath.Join(readyRoot, id+"-ready.json")
	ready, err := readOptionalDatabaseFile(readyPath)
	if err == nil {
		var prepared databasePrepared
		if err := strictjson.Decode(ready, &prepared, 1<<20); err != nil {
			return zero, err
		}
		if !safeRelative(prepared.Path) || !strings.HasPrefix(prepared.Path, "databases/"+id+"/") || !digestPattern.MatchString(strings.TrimPrefix(prepared.Digest, "sha256:")) || !strings.HasPrefix(prepared.Digest, "sha256:") {
			return zero, errors.New("invalid completed database identity")
		}
		if err := databaseFresh(prepared.At, time.Now()); err != nil {
			return zero, err
		}
		if err := runner.VerifyDatabaseSnapshot(filepath.Join(toolsRoot, filepath.FromSlash(prepared.Path)), prepared.Digest, id); err != nil {
			return zero, err
		}
		metadataBytes, err := readBounded(filepath.Join(toolsRoot, filepath.FromSlash(prepared.Path), "metadata.json"), 1<<20)
		if err != nil {
			return zero, err
		}
		var metadata preparedDatabaseMetadata
		if err := strictjson.Decode(metadataBytes, &metadata, 1<<20); err != nil {
			return zero, err
		}
		lockedSource, _ := json.Marshal(lock)
		completedSource, _ := json.Marshal(metadata.Source)
		if !bytes.Equal(lockedSource, completedSource) || !metadata.BuiltAt.Equal(prepared.At) || !digestPattern.MatchString(metadata.ArchiveSHA256) || (lock.SHA256 != "" && metadata.ArchiveSHA256 != lock.SHA256) {
			return zero, errors.New("completed database source differs from immutable lock")
		}
		if !sameDatabaseEnvironment(prepared.Environment, databaseEnvironment(id)) {
			return zero, errors.New("completed database environment differs")
		}
		if id == "osv-scanner" {
			if err := validateOSVDatabaseLayout(metadata); err != nil {
				return zero, err
			}
		}
		return prepared, nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}

	var archive string
	err = nil
	if id == "osv-scanner" {
		archive, err = fetchOSVGeneration(ctx, d, cache, lock)
	} else {
		var headers map[string]string
		if id == "trivy" {
			// A verified archive in the shared cache needs no registry token,
			// including when materializing another tools generation offline.
			if _, statErr := os.Lstat(filepath.Join(cache, lock.SHA256+"-"+lock.Filename)); os.IsNotExist(statErr) {
				headers, err = trivyHeaders(ctx, d)
			} else if statErr != nil {
				err = statErr
			}
		}
		if err == nil {
			archive, err = d.fetch(ctx, Artifact{ID: id + "-database", URL: lock.URL, SHA256: lock.SHA256, Bytes: lock.Bytes, Filename: lock.Filename}, cache, headers)
		}
	}
	if err != nil {
		return zero, err
	}
	archiveDigest, err := hashFile(archive, databaseArchiveLimit)
	if err != nil {
		return zero, err
	}
	parent := filepath.Join(toolsRoot, "databases", id)
	if err := privateTree(parent); err != nil {
		return zero, err
	}
	// Failed extraction/hydration generations are retained and never overwritten.
	root, err := os.MkdirTemp(parent, hashBytes(raw)[:16]+"-")
	if err != nil {
		return zero, err
	}
	if err := privateDir(root); err != nil {
		return zero, err
	}
	at := lock.At
	switch id {
	case "grype":
		input, createErr := os.MkdirTemp(cache, "grype-input-")
		if createErr != nil {
			return zero, createErr
		}
		if err := privateDir(input); err != nil {
			return zero, err
		}
		if err := extractDatabaseTar(ctx, archive, input, lock.Format, map[string]bool{"vulnerability.db": true}); err != nil {
			return zero, err
		}
		if err := hydrate(ctx, filepath.Join(input, "vulnerability.db"), root); err != nil {
			return zero, err
		}
		for _, name := range []string{"6/vulnerability.db", "6/import.json"} {
			if _, err := hashFile(filepath.Join(root, filepath.FromSlash(name)), databaseExpandedLimit); err != nil {
				return zero, fmt.Errorf("Grype import did not produce %s", name)
			}
		}
	case "trivy":
		dbDir := filepath.Join(root, "db")
		if err := privateTree(dbDir); err != nil {
			return zero, err
		}
		if err := extractDatabaseTar(ctx, archive, dbDir, lock.Format, map[string]bool{"trivy.db": true, "metadata.json": true}); err != nil {
			return zero, err
		}
		b, err := readBounded(filepath.Join(dbDir, "metadata.json"), 1<<20)
		if err != nil {
			return zero, err
		}
		var metadata struct {
			Version      int       `json:"Version"`
			NextUpdate   time.Time `json:"NextUpdate"`
			UpdatedAt    time.Time `json:"UpdatedAt"`
			DownloadedAt time.Time `json:"DownloadedAt"`
		}
		if err := strictjson.Decode(b, &metadata, 1<<20); err != nil {
			return zero, err
		}
		if metadata.Version != 2 || !metadata.NextUpdate.After(metadata.UpdatedAt) {
			return zero, errors.New("unsupported Trivy database metadata")
		}
		at = metadata.UpdatedAt // Never substitute the download time for database age.
	case "osv-scanner":
		if err := verifyOSVZip(ctx, archive); err != nil {
			return zero, err
		}
		if err := copyExact(archive, filepath.Join(root, filepath.FromSlash(osvArchivePath)), archiveDigest, databaseArchiveLimit); err != nil {
			return zero, err
		}
	default:
		return zero, errors.New("unknown database")
	}
	if err := databaseFresh(at, time.Now()); err != nil {
		return zero, err
	}
	files, err := inventory(root, "metadata.json")
	if err != nil || len(files) == 0 {
		return zero, errors.New("prepared database inventory failed")
	}
	metadata := preparedDatabaseMetadata{databaseMetadataVersion, id, files, at, lock, archiveDigest}
	if id == "osv-scanner" {
		if err := validateOSVDatabaseLayout(metadata); err != nil {
			return zero, err
		}
	}
	b, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return zero, err
	}
	if err := writeOnce(filepath.Join(root, "metadata.json"), b); err != nil {
		return zero, err
	}
	rel, err := filepath.Rel(toolsRoot, root)
	if err != nil {
		return zero, err
	}
	prepared := databasePrepared{Path: filepath.ToSlash(rel), Digest: "sha256:" + hashBytes(b), At: at, Environment: databaseEnvironment(id)}
	if err := runner.VerifyDatabaseSnapshot(root, prepared.Digest, id); err != nil {
		return zero, err
	}
	b, err = json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		return zero, err
	}
	if err := writeOnce(readyPath, b); err != nil {
		return zero, err
	}
	return prepared, nil
}

// Integrity alone cannot establish compatibility: the old osv-scanner/Go
// layout can be correctly sealed yet require a write to the read-only mount.
// Reject it without changing its archive, marker, timestamp or approval.
func validateOSVDatabaseLayout(metadata preparedDatabaseMetadata) error {
	if metadata.Tool != "osv-scanner" || len(metadata.Files) != 1 || metadata.Files[0].Path != osvArchivePath || !digestPattern.MatchString(metadata.ArchiveSHA256) || metadata.Files[0].SHA256 != metadata.ArchiveSHA256 {
		return errors.New("OSV database layout is incompatible with the pinned scanner; prepare a fresh installation generation")
	}
	return nil
}

func verifyPreparedDatabaseLayout(root, toolID string) error {
	if toolID != "osv-scanner" {
		return nil
	}
	raw, err := readBounded(filepath.Join(root, "metadata.json"), 1<<20)
	if err != nil {
		return err
	}
	var metadata preparedDatabaseMetadata
	if err := strictjson.Decode(raw, &metadata, 1<<20); err != nil {
		return err
	}
	return validateOSVDatabaseLayout(metadata)
}

func readOptionalDatabaseFile(path string) ([]byte, error) {
	// CheckPath intentionally redacts filesystem failures, so preserve ENOENT
	// only for the optional immutable lock/completion marker lookup itself.
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return readBounded(path, 1<<20)
}

func databaseEnvironment(id string) map[string]string {
	switch id {
	case "grype":
		return map[string]string{"GRYPE_DB_CACHE_DIR": "/pao/database", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
	case "osv-scanner":
		return map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/pao/database"}
	default:
		return map[string]string{}
	}
}

func sameDatabaseEnvironment(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

func databaseFresh(at, now time.Time) error {
	if at.IsZero() || at.After(now.UTC()) || now.UTC().Sub(at) > toolchain.MaximumPrerequisiteAge {
		return errors.New("upstream database timestamp is missing, future or stale")
	}
	return nil
}

func validateDatabaseLock(l databaseLock, id string, now time.Time) error {
	if l.Version != databaseLockVersion || l.Tool != id || l.Bytes <= 0 || l.Bytes > databaseArchiveLimit || !digestPattern.MatchString(l.MetadataSHA256) || !safeRelative(l.Filename) || filepath.Base(l.Filename) != l.Filename {
		return errors.New("invalid database download lock")
	}
	if err := databaseFresh(l.ResolvedAt, now); err != nil {
		return err
	}
	if id != "trivy" {
		if err := databaseFresh(l.At, now); err != nil {
			return err
		}
	}
	if err := publicURL(l.URL); err != nil {
		return err
	}
	u, err := url.Parse(l.URL)
	if err != nil {
		return err
	}
	switch id {
	case "grype":
		if u.Host != "grype.anchore.io" || !grypeArchiveMember(l.RemoteFilename) || u.Path != "/databases/v6/"+l.RemoteFilename || u.RawQuery != "" || !digestPattern.MatchString(l.SHA256) || (l.Format != "tar.zst" && l.Format != "tar.gz") || l.Filename != "grype-db."+l.Format || !strings.HasSuffix(l.RemoteFilename, "."+l.Format) {
			return errors.New("invalid Grype database lock")
		}
	case "trivy":
		if u.Host != "ghcr.io" || u.Path != "/v2/aquasecurity/trivy-db/blobs/sha256:"+l.SHA256 || u.RawQuery != "" || !digestPattern.MatchString(l.SHA256) || l.Format != "tar.gz" || l.Filename != "trivy-db.tar.gz" {
			return errors.New("invalid Trivy database lock")
		}
	case "osv-scanner":
		md, me := base64.StdEncoding.DecodeString(l.MD5)
		crc, ce := base64.StdEncoding.DecodeString(l.CRC32C)
		if u.Host != "storage.googleapis.com" || u.EscapedPath() != "/download/storage/v1/b/osv-vulnerabilities/o/Go%2Fall.zip" || u.Query().Get("generation") != l.Generation || u.Query().Get("alt") != "media" || len(u.Query()) != 2 || !regexp.MustCompile(`^[1-9][0-9]{0,24}$`).MatchString(l.Generation) || me != nil || len(md) != 16 || ce != nil || len(crc) != 4 || l.SHA256 != "" || l.Format != "zip" || l.Filename != "osv-Go-all.zip" {
			return errors.New("invalid OSV immutable generation lock")
		}
	default:
		return errors.New("unknown database lock identity")
	}
	return nil
}

func resolveDatabase(ctx context.Context, d *downloader, id string) (databaseLock, error) {
	l := databaseLock{Version: databaseLockVersion, Tool: id, ResolvedAt: time.Now().UTC()}
	switch id {
	case "grype":
		b, _, err := d.get(ctx, grypeListingURL, 1<<20, nil)
		if err != nil {
			return l, err
		}
		var metadata struct {
			Status   string    `json:"status"`
			Schema   string    `json:"schemaVersion"`
			Built    time.Time `json:"built"`
			Path     string    `json:"path"`
			Checksum string    `json:"checksum"`
		}
		if err := strictjson.Decode(b, &metadata, 1<<20); err != nil {
			return l, err
		}
		if metadata.Status != "active" || !regexp.MustCompile(`^v6\.[0-9]+\.[0-9]+$`).MatchString(metadata.Schema) || !strings.HasPrefix(metadata.Checksum, "sha256:") {
			return l, errors.New("unsupported Grype distribution metadata")
		}
		// Upstream names contain RFC3339 colons, which are valid URL path
		// characters but cannot be used as Windows filenames.
		if !grypeArchiveMember(metadata.Path) {
			return l, errors.New("unsafe Grype archive member")
		}
		remote := url.URL{Scheme: "https", Host: "grype.anchore.io", Path: "/databases/v6/" + metadata.Path}
		l.URL, l.RemoteFilename = remote.String(), metadata.Path
		l.SHA256, l.At, l.MetadataSHA256 = strings.TrimPrefix(metadata.Checksum, "sha256:"), metadata.Built, hashBytes(b)
		if strings.HasSuffix(metadata.Path, ".tar.zst") {
			l.Format = "tar.zst"
		} else if strings.HasSuffix(metadata.Path, ".tar.gz") {
			l.Format = "tar.gz"
		} else {
			return l, errors.New("unsupported Grype database archive")
		}
		l.Filename = "grype-db." + l.Format
		l.Bytes, err = databaseContentLength(ctx, d, l.URL)
		if err != nil {
			return l, err
		}
	case "trivy":
		headers, err := trivyHeaders(ctx, d)
		if err != nil {
			return l, err
		}
		headers["Accept"] = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
		b, h, err := d.get(ctx, trivyManifestURL, 1<<20, headers)
		if err != nil {
			return l, err
		}
		if h.Get("Docker-Content-Digest") != "sha256:"+hashBytes(b) {
			return l, errors.New("Trivy manifest SHA-256 mismatch")
		}
		type descriptor struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations,omitempty"`
			Data        string            `json:"data,omitempty"`
		}
		var manifest struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType"`
			ArtifactType  string            `json:"artifactType,omitempty"`
			Config        descriptor        `json:"config"`
			Layers        []descriptor      `json:"layers"`
			Annotations   map[string]string `json:"annotations,omitempty"`
		}
		if err := strictjson.Decode(b, &manifest, 1<<20); err != nil {
			return l, err
		}
		if manifest.SchemaVersion != 2 || len(manifest.Layers) != 1 || (manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" && manifest.MediaType != "application/vnd.docker.distribution.manifest.v2+json") {
			return l, errors.New("unsupported Trivy OCI manifest")
		}
		layer := manifest.Layers[0]
		if layer.MediaType != "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip" || !strings.HasPrefix(layer.Digest, "sha256:") {
			return l, errors.New("unsupported Trivy OCI database layer")
		}
		l.SHA256, l.Bytes, l.Filename, l.Format, l.MetadataSHA256 = strings.TrimPrefix(layer.Digest, "sha256:"), layer.Size, "trivy-db.tar.gz", "tar.gz", hashBytes(b)
		l.URL = "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/" + layer.Digest
	case "osv-scanner":
		b, _, err := d.get(ctx, osvObjectURL, 1<<20, nil)
		if err != nil {
			return l, err
		}
		var metadata struct {
			Kind            string            `json:"kind"`
			ID              string            `json:"id"`
			SelfLink        string            `json:"selfLink"`
			MediaLink       string            `json:"mediaLink"`
			Name            string            `json:"name"`
			Bucket          string            `json:"bucket"`
			Generation      string            `json:"generation"`
			Metageneration  string            `json:"metageneration"`
			ContentType     string            `json:"contentType"`
			StorageClass    string            `json:"storageClass"`
			Size            string            `json:"size"`
			MD5             string            `json:"md5Hash"`
			CRC32C          string            `json:"crc32c"`
			ETag            string            `json:"etag"`
			Created         time.Time         `json:"timeCreated"`
			Updated         time.Time         `json:"updated"`
			StorageUpdated  time.Time         `json:"timeStorageClassUpdated"`
			Finalized       time.Time         `json:"timeFinalized"`
			ContentEncoding string            `json:"contentEncoding,omitempty"`
			CacheControl    string            `json:"cacheControl,omitempty"`
			Metadata        map[string]string `json:"metadata,omitempty"`
		}
		if err := strictjson.Decode(b, &metadata, 1<<20); err != nil {
			return l, err
		}
		if metadata.Kind != "storage#object" || metadata.Bucket != "osv-vulnerabilities" || metadata.Name != "Go/all.zip" || metadata.ContentEncoding != "" {
			return l, errors.New("unexpected OSV object identity or encoding")
		}
		l.Bytes, err = strconv.ParseInt(metadata.Size, 10, 64)
		if err != nil {
			return l, errors.New("invalid OSV size")
		}
		l.Generation, l.MD5, l.CRC32C, l.At = metadata.Generation, metadata.MD5, metadata.CRC32C, metadata.Created
		l.MetadataSHA256, l.Filename, l.Format = hashBytes(b), "osv-Go-all.zip", "zip"
		l.URL = "https://storage.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/Go%2Fall.zip?alt=media&generation=" + url.QueryEscape(metadata.Generation)
	default:
		return l, errors.New("unsupported database")
	}
	return l, validateDatabaseLock(l, id, time.Now())
}

func grypeArchiveMember(name string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\.tar\.(zst|gz)$`).MatchString(name)
}

func trivyHeaders(ctx context.Context, d *downloader) (map[string]string, error) {
	b, _, err := d.get(ctx, "https://ghcr.io/token?service=ghcr.io&scope=repository:aquasecurity/trivy-db:pull", 1<<20, nil)
	if err != nil {
		return nil, err
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token,omitempty"`
		Expires     int    `json:"expires_in,omitempty"`
		Issued      string `json:"issued_at,omitempty"`
	}
	if err := strictjson.Decode(b, &token, 1<<20); err != nil {
		return nil, err
	}
	if len(token.Token) < 1 || len(token.Token) > 16384 || strings.ContainsAny(token.Token, "\r\n") {
		return nil, errors.New("invalid anonymous registry token")
	}
	return map[string]string{"Authorization": "Bearer " + token.Token}, nil
}

func databaseContentLength(ctx context.Context, d *downloader, raw string) (int64, error) {
	if err := publicURL(raw); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, raw, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := d.client.Do(req)
	if err != nil {
		return 0, errors.New("database size preflight failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength <= 0 || response.ContentLength > databaseArchiveLimit {
		return 0, errors.New("database size is unavailable or exceeds limit")
	}
	return response.ContentLength, nil
}

func fetchOSVGeneration(ctx context.Context, d *downloader, cache string, l databaseLock) (string, error) {
	dest := filepath.Join(cache, "osv-Go-"+l.Generation+".zip")
	if _, err := os.Lstat(dest); err == nil {
		if err := verifyOSVContent(ctx, dest, l); err != nil {
			return "", err
		}
		return dest, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept-Encoding", "identity")
	r, err := d.client.Do(req)
	if err != nil {
		return "", errors.New("OSV immutable download failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || r.ContentLength > l.Bytes || (r.Header.Get("X-Goog-Generation") != "" && r.Header.Get("X-Goog-Generation") != l.Generation) {
		return "", errors.New("OSV download status, generation or size mismatch")
	}
	f, err := os.CreateTemp(cache, "osv-Go-*.partial")
	if err != nil {
		return "", err
	}
	partial := f.Name()
	n, copyErr := io.Copy(f, io.LimitReader(&databaseContextReader{ctx, r.Body}, l.Bytes+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return "", err
	}
	if n != l.Bytes {
		return "", errors.New("OSV download size mismatch; partial retained")
	}
	if err := verifyOSVContent(ctx, partial, l); err != nil {
		return "", err
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		return "", errors.New("OSV destination already exists")
	}
	if err := os.Rename(partial, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func verifyOSVContent(ctx context.Context, path string, l databaseLock) error {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != l.Bytes {
		return errors.New("OSV generation byte mismatch")
	}
	md, crc := md5.New(), crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, err := io.Copy(io.MultiWriter(md, crc), io.LimitReader(&databaseContextReader{ctx, f}, l.Bytes+1))
	if err != nil || n != l.Bytes || base64.StdEncoding.EncodeToString(md.Sum(nil)) != l.MD5 || base64.StdEncoding.EncodeToString(crc.Sum(nil)) != l.CRC32C {
		return errors.New("OSV provider content digest mismatch")
	}
	return nil
}

type databaseContextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r *databaseContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(p)
}

// Only the expected database filenames are extracted. No archive-provided path
// can select a directory, link, executable or host location. Every stream is
// drained within bounds so gzip/Zstandard frame checksums are verified too.
func extractDatabaseTar(ctx context.Context, archive, root, format string, required map[string]bool) error {
	if err := auditconfig.CheckPath(archive, false); err != nil {
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > databaseArchiveLimit {
		return errors.New("database archive input bound")
	}
	var stream io.Reader = &databaseContextReader{ctx, f}
	switch format {
	case "tar.gz":
		gz, err := gzip.NewReader(stream)
		if err != nil {
			return err
		}
		defer gz.Close()
		stream = gz
	case "tar.zst":
		stream = zstd.NewReader(stream)
	default:
		return errors.New("unsupported database compression")
	}
	bounded := &limitedRead{r: &databaseContextReader{ctx, stream}, left: databaseExpandedLimit + (1 << 20)}
	tr := tar.NewReader(bounded)
	seen := map[string]bool{}
	var total int64
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		count++
		if count > 32 {
			return errors.New("database tar entry count bound")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name == "." || name == "" {
			if h.Typeflag == tar.TypeDir {
				continue
			}
		}
		if !required[name] || seen[name] || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || h.Size <= 0 || h.Size > databaseExpandedLimit || total > databaseExpandedLimit-h.Size {
			return errors.New("unexpected, duplicate, special or oversized database archive member")
		}
		for key := range h.PAXRecords {
			if key != "mtime" && key != "atime" && key != "ctime" {
				return errors.New("unsupported database PAX metadata")
			}
		}
		seen[name], total = true, total+h.Size
		path := filepath.Join(root, name)
		if err := auditconfig.CheckPath(path, true); err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, copyErr := io.CopyN(out, tr, h.Size)
		syncErr := out.Sync()
		closeErr := out.Close()
		if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
			return err
		}
		if n != h.Size {
			return errors.New("truncated database member")
		}
	}
	if len(seen) != len(required) {
		return errors.New("required database archive file absent")
	}
	_, err = io.Copy(io.Discard, bounded)
	return err
}

func verifyOSVZip(ctx context.Context, path string) error {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 22 || info.Size() > databaseArchiveLimit {
		return errors.New("OSV archive byte bound")
	}
	// Inspect the central-directory envelope before archive/zip allocates file
	// objects. Go-only exports fit classic ZIP; ZIP64 and multidisk inputs fail.
	tailSize := min(info.Size(), 65557)
	tail := make([]byte, tailSize)
	if _, err := f.ReadAt(tail, info.Size()-tailSize); err != nil {
		return err
	}
	end := bytes.LastIndex(tail, []byte{'P', 'K', 5, 6})
	if end < 0 || len(tail)-end < 22 {
		return errors.New("OSV ZIP end record absent")
	}
	eocd := tail[end:]
	entryCount := int(binary.LittleEndian.Uint16(eocd[10:12]))
	centralSize := int64(binary.LittleEndian.Uint32(eocd[12:16]))
	centralOffset := int64(binary.LittleEndian.Uint32(eocd[16:20]))
	if binary.LittleEndian.Uint16(eocd[4:6]) != 0 || binary.LittleEndian.Uint16(eocd[6:8]) != 0 || int(binary.LittleEndian.Uint16(eocd[8:10])) != entryCount || entryCount == 0 || entryCount > 60000 || centralSize > 32<<20 || centralOffset+centralSize != info.Size()-tailSize+int64(end) || int(binary.LittleEndian.Uint16(eocd[20:22])) != len(eocd)-22 {
		return errors.New("OSV ZIP directory or entry bound")
	}
	reader, err := zip.NewReader(f, info.Size())
	if err != nil {
		return err
	}
	if len(reader.File) != entryCount {
		return errors.New("OSV entry count bound")
	}
	seen := map[string]bool{}
	var total uint64
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := strings.ToLower(entry.Name)
		if !safeRelative(entry.Name) || strings.Contains(entry.Name, "/") || !strings.HasSuffix(entry.Name, ".json") || seen[key] || !entry.Mode().IsRegular() || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > 8<<20 || total > uint64(databaseExpandedLimit)-entry.UncompressedSize64 {
			return errors.New("unsafe, duplicate or oversized OSV ZIP member")
		}
		seen[key], total = true, total+entry.UncompressedSize64
		r, err := entry.Open()
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(io.Discard, io.LimitReader(&databaseContextReader{ctx, r}, int64(entry.UncompressedSize64)+1))
		closeErr := r.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if n != int64(entry.UncompressedSize64) {
			return errors.New("OSV ZIP member length mismatch")
		}
	}
	return nil
}
