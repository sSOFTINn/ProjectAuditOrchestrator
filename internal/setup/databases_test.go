package setup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type databaseTransport func(*http.Request) (*http.Response, error)

func (f databaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testDatabaseTar(t *testing.T, names []string, contents map[string][]byte, compression string) []byte {
	t.Helper()
	var data bytes.Buffer
	tw := tar.NewWriter(&data)
	for _, name := range names {
		b := contents[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if compression == "tar.zst" {
		// One standard raw Zstandard block exercises the actual vendored decoder.
		n := data.Len()
		if n < 256 || n > 65536 {
			t.Fatal("fixture frame length")
		}
		frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x60, 0, 0, 0, 0, 0}
		binary.LittleEndian.PutUint16(frame[5:7], uint16(n-256))
		header := uint32(n)<<3 | 1
		frame[7], frame[8], frame[9] = byte(header), byte(header>>8), byte(header>>16)
		return append(frame, data.Bytes()...)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(data.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func testOSVZip(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	writer := zip.NewWriter(&b)
	for _, name := range names {
		f, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, `{"id":"SYNTHETIC-1"}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testDatabaseDownloader(t *testing.T, stamp time.Time) (*downloader, *int) {
	t.Helper()
	grype := testDatabaseTar(t, []string{"vulnerability.db"}, map[string][]byte{"vulnerability.db": []byte("synthetic Grype database")}, "tar.zst")
	trivyMetadata, _ := json.Marshal(map[string]any{"Version": 2, "NextUpdate": stamp.Add(6 * time.Hour), "UpdatedAt": stamp, "DownloadedAt": time.Time{}})
	trivy := testDatabaseTar(t, []string{"trivy.db", "metadata.json"}, map[string][]byte{"trivy.db": []byte("synthetic Trivy database"), "metadata.json": trivyMetadata}, "tar.gz")
	osv := testOSVZip(t, "SYNTHETIC-1.json")
	md := md5.Sum(osv)
	crc := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = crc.Write(osv)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:" + hashBytes([]byte("{}")), "size": 2}, "layers": []map[string]any{{"mediaType": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", "digest": "sha256:" + hashBytes(trivy), "size": len(trivy)}}})
	grypeMetadata, _ := json.Marshal(map[string]any{"status": "active", "schemaVersion": "v6.1.10", "built": stamp, "path": "synthetic.tar.zst", "checksum": "sha256:" + hashBytes(grype)})
	osvMetadata, _ := json.Marshal(map[string]any{"kind": "storage#object", "bucket": "osv-vulnerabilities", "name": "Go/all.zip", "generation": "123456", "size": lenString(osv), "md5Hash": base64.StdEncoding.EncodeToString(md[:]), "crc32c": base64.StdEncoding.EncodeToString(crc.Sum(nil)), "timeCreated": stamp})
	requests := 0
	d := &downloader{client: &http.Client{Transport: databaseTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		var b []byte
		headers := http.Header{}
		switch r.URL.String() {
		case grypeListingURL:
			b = grypeMetadata
		case "https://grype.anchore.io/databases/v6/synthetic.tar.zst":
			b = grype
		case "https://ghcr.io/token?service=ghcr.io&scope=repository:aquasecurity/trivy-db:pull":
			b = []byte(`{"token":"synthetic-anonymous-token"}`)
		case trivyManifestURL:
			if r.Header.Get("Authorization") == "" {
				t.Error("missing registry token")
			}
			b = manifest
			headers.Set("Docker-Content-Digest", "sha256:"+hashBytes(b))
		case "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:" + hashBytes(trivy):
			b = trivy
		case osvObjectURL:
			b = osvMetadata
		case "https://storage.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/Go%2Fall.zip?alt=media&generation=123456":
			b = osv
			headers.Set("X-Goog-Generation", "123456")
		default:
			return nil, errors.New("unexpected test request")
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(b)), Header: headers, Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
	})}}
	return d, &requests
}

func lenString(b []byte) string { return strconv.Itoa(len(b)) }

func syntheticDatabaseHydrator(ctx context.Context, source, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := privateTree(filepath.Join(destination, "6")); err != nil {
		return err
	}
	if err := writeOnce(filepath.Join(destination, "6", "vulnerability.db"), b); err != nil {
		return err
	}
	return writeOnce(filepath.Join(destination, "6", "import.json"), []byte(`{"synthetic":true}`))
}

func TestPrepareDatabasesSealsUpstreamAgeAndResumesOffline(t *testing.T) {
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	d, calls := testDatabaseDownloader(t, stamp)
	base := t.TempDir()
	cache, root := filepath.Join(base, "cache"), filepath.Join(base, "tools")
	prepared, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 3 {
		t.Fatalf("prepared: %+v", prepared)
	}
	for id, value := range prepared {
		if !value.At.Equal(stamp) || !strings.HasPrefix(value.Digest, "sha256:") {
			t.Fatalf("%s lost upstream timestamp or digest", id)
		}
		metadata, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(value.Path), "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(metadata, []byte(`"archive_sha256"`)) {
			t.Fatal("computed SHA-256 absent")
		}
	}
	before := *calls
	if _, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator); err != nil {
		t.Fatal(err)
	}
	if *calls != before {
		t.Fatal("completed preparation contacted network")
	}
	lockPath := filepath.Join(cache, "database-grype-lock.json")
	locked, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var changed databaseLock
	if err := json.Unmarshal(locked, &changed); err != nil {
		t.Fatal(err)
	}
	changed.ResolvedAt = changed.ResolvedAt.Add(-time.Minute)
	changedBytes, _ := json.Marshal(changed)
	if err := os.WriteFile(lockPath, changedBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator); err == nil || !strings.Contains(err.Error(), "source differs") {
		t.Fatalf("completion not bound to source lock: %v", err)
	}
	if err := os.WriteFile(lockPath, locked, 0600); err != nil {
		t.Fatal(err)
	}
	// A matching completion marker never excuses changed database bytes.
	path := filepath.Join(root, filepath.FromSlash(prepared["trivy"].Path), "db", "trivy.db")
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator); err == nil {
		t.Fatal("tampered completion accepted")
	}
}

func TestDatabaseCompletionBelongsToGenerationWithSharedOfflineCache(t *testing.T) {
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	d, _ := testDatabaseDownloader(t, stamp)
	base := t.TempDir()
	cache := filepath.Join(base, "cache")
	firstRoot, secondRoot := filepath.Join(base, "generation-one", "tools"), filepath.Join(base, "generation-two", "tools")
	first, err := prepareDatabases(context.Background(), d, cache, firstRoot, syntheticDatabaseHydrator)
	if err != nil {
		t.Fatal(err)
	}
	firstMarkers := map[string][]byte{}
	for id := range first {
		marker, err := os.ReadFile(filepath.Join(firstRoot, "database-preparation", id+"-ready.json"))
		if err != nil {
			t.Fatal(err)
		}
		firstMarkers[id] = marker
	}
	// Old packages used a shared ready marker. Preserve it as evidence, but
	// never treat its generation-relative path as a new generation's output.
	legacyMarker := filepath.Join(cache, "database-grype-ready.json")
	legacyBytes := []byte(`{"path":"databases/grype/from-another-generation"}`)
	if err := os.WriteFile(legacyMarker, legacyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	d.client.Transport = databaseTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("network disabled after initial cache preparation")
	})
	second, err := prepareDatabases(context.Background(), d, cache, secondRoot, syntheticDatabaseHydrator)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Fatal("new generation lost database coverage")
	}
	for id, prepared := range second {
		if prepared.Path == first[id].Path || !prepared.At.Equal(first[id].At) || prepared.Digest != first[id].Digest {
			t.Fatalf("%s did not materialize a distinct generation of the same immutable source", id)
		}
		before, err := os.ReadFile(filepath.Join(firstRoot, "database-preparation", id+"-ready.json"))
		if err != nil || !bytes.Equal(before, firstMarkers[id]) {
			t.Fatalf("%s first completion marker changed", id)
		}
	}
	for _, root := range []string{firstRoot, secondRoot} {
		if _, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator); err != nil {
			t.Fatalf("generation resume failed: %v", err)
		}
	}
	if requests != 0 {
		t.Fatal("shared verified cache or generation resume contacted network")
	}
	retained, err := os.ReadFile(legacyMarker)
	if err != nil || !bytes.Equal(retained, legacyBytes) {
		t.Fatal("legacy completion evidence changed")
	}
}

func TestDatabaseLocksPrecedeDownloadAndKeepPartialAttempts(t *testing.T) {
	d, _ := testDatabaseDownloader(t, time.Now().UTC().Add(-time.Hour))
	base := t.TempDir()
	cache, root := filepath.Join(base, "cache"), filepath.Join(base, "tools")
	if _, err := prepareDatabases(context.Background(), d, cache, root, func(_ context.Context, source, destination string) error {
		if _, err := os.Stat(filepath.Join(cache, "database-grype-lock.json")); err != nil {
			t.Fatal("payload arrived before lock")
		}
		return errors.New("synthetic interrupted hydration")
	}); err == nil {
		t.Fatal("failed hydration accepted")
	}
	attempts, _ := filepath.Glob(filepath.Join(root, "databases", "grype", "*"))
	if len(attempts) != 1 {
		t.Fatal("failed generation not retained")
	}
	if _, err := prepareDatabases(context.Background(), d, cache, root, syntheticDatabaseHydrator); err != nil {
		t.Fatal(err)
	}
	after, _ := filepath.Glob(filepath.Join(root, "databases", "grype", "*"))
	if len(after) != 2 {
		t.Fatal("retry reused or removed partial generation")
	}
}

func TestDatabaseArchiveRejectsAliasesPathsAndTruncation(t *testing.T) {
	for _, names := range [][]string{{"../vulnerability.db"}, {"vulnerability.db", "vulnerability.db"}, {"VULNERABILITY.DB"}, {"other.db"}} {
		contents := map[string][]byte{}
		for _, name := range names {
			contents[name] = []byte("synthetic")
		}
		base := t.TempDir()
		archive := filepath.Join(base, "input.tar.gz")
		root := filepath.Join(base, "output")
		if err := privateTree(root); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archive, testDatabaseTar(t, names, contents, "tar.gz"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := extractDatabaseTar(context.Background(), archive, root, "tar.gz", map[string]bool{"vulnerability.db": true}); err == nil {
			t.Fatalf("unsafe names accepted: %v", names)
		}
	}
	base := t.TempDir()
	archive := filepath.Join(base, "input.tar.gz")
	root := filepath.Join(base, "output")
	_ = privateTree(root)
	b := testDatabaseTar(t, []string{"vulnerability.db"}, map[string][]byte{"vulnerability.db": []byte("synthetic")}, "tar.gz")
	if err := os.WriteFile(archive, b[:len(b)-3], 0600); err != nil {
		t.Fatal(err)
	}
	if err := extractDatabaseTar(context.Background(), archive, root, "tar.gz", map[string]bool{"vulnerability.db": true}); err == nil {
		t.Fatal("gzip checksum truncation accepted")
	}
}

func TestOSVArchiveAndFreshnessFailClosed(t *testing.T) {
	for _, names := range [][]string{{"../bad.json"}, {"a.json", "A.json"}, {"script.exe"}} {
		path := filepath.Join(t.TempDir(), "input.zip")
		if err := os.WriteFile(path, testOSVZip(t, names...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyOSVZip(context.Background(), path); err == nil {
			t.Fatalf("unsafe OSV entries accepted: %v", names)
		}
	}
	zip64 := testOSVZip(t, "SYNTHETIC.json")
	eocd := bytes.LastIndex(zip64, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint16(zip64[eocd+8:eocd+10], 65535)
	binary.LittleEndian.PutUint16(zip64[eocd+10:eocd+12], 65535)
	path := filepath.Join(t.TempDir(), "oversized-directory.zip")
	if err := os.WriteFile(path, zip64, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyOSVZip(context.Background(), path); err == nil || !strings.Contains(err.Error(), "directory or entry bound") {
		t.Fatalf("ZIP directory allocation preflight absent: %v", err)
	}
	now := time.Now()
	for _, stamp := range []time.Time{{}, now.Add(time.Minute), now.Add(-91 * 24 * time.Hour)} {
		if databaseFresh(stamp, now) == nil {
			t.Fatal("invalid upstream timestamp accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&databaseContextReader{ctx, strings.NewReader("synthetic")}).Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored")
	}
}

func TestDatabaseTarRejectsLinksAndOversizedMembersBeforeWriting(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "vulnerability.db", Typeflag: tar.TypeSymlink, Linkname: "outside", Mode: 0600},
		{Name: "vulnerability.db", Typeflag: tar.TypeReg, Size: databaseExpandedLimit + 1, Mode: 0600},
	} {
		var tarData bytes.Buffer
		writer := tar.NewWriter(&tarData)
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		var zipped bytes.Buffer
		gz := gzip.NewWriter(&zipped)
		if _, err := gz.Write(tarData.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		base := t.TempDir()
		root, path := filepath.Join(base, "output"), filepath.Join(base, "input.tar.gz")
		if err := privateTree(root); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, zipped.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		if err := extractDatabaseTar(context.Background(), path, root, "tar.gz", map[string]bool{"vulnerability.db": true}); err == nil {
			t.Fatal("unsafe member accepted")
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("unsafe member wrote output")
		}
	}
}

func TestDatabaseOfficialMetadataIntegration(t *testing.T) {
	if os.Getenv("PAO_DATABASE_METADATA_INTEGRATION") != "1" {
		t.Skip("explicit public-metadata network check only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, id := range []string{"grype", "trivy", "osv-scanner"} {
		lock, err := resolveDatabase(ctx, newDownloader(), id)
		if err != nil {
			t.Fatalf("%s metadata: %v", id, err)
		}
		if strings.ContainsAny(lock.Filename, `\\/:`) {
			t.Fatal("upstream URL leaked into Windows cache filename")
		}
		t.Logf("%s official metadata resolved: %s, %d bytes; no payload downloaded", id, lock.Format, lock.Bytes)
	}
}
