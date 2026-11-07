// Package installation owns the private, durable lifecycle of one PAO installation.
package installation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/strictjson"
)

const Version = "pao.dev/installation/v1"
const RunVersion = "pao.dev/container-lifecycle/v1"
const maxRecordBytes = 64 << 10
const maxRuns = 100000

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type manifest struct {
	Version   string    `json:"version"`
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// Run is retained after verified teardown. It never contains target contents,
// credentials, environment variables or scanner output.
type Run struct {
	Version        string    `json:"version"`
	ID             string    `json:"id"`
	InstallationID string    `json:"installation_id"`
	AuditID        string    `json:"audit_id"`
	ContainerName  string    `json:"container_name"`
	ContainerID    string    `json:"container_id,omitempty"`
	Endpoint       string    `json:"endpoint"`
	RuntimeImage   string    `json:"runtime_image"`
	DockerPath     string    `json:"docker_path"`
	DockerSHA256   string    `json:"docker_sha256"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Store struct{ root, id string }
type Lease struct {
	store     *Store
	file      *os.File
	exclusive bool
}

func (s *Store) ID() string   { return s.id }
func (s *Store) Root() string { return s.root }

// Initialize is a setup operation. It never changes permissions of an existing
// path or repairs an ambiguous partial installation in place.
func Initialize(root string) (*Store, error) {
	if err := auditconfig.CheckPath(root, true); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		if err := auditconfig.MakePrivateDirectory(root); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := ValidatePrivatePath(root, true); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return Open(root)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	if err := auditconfig.MakePrivateDirectory(filepath.Join(root, "runs")); err != nil {
		return nil, err
	}
	if err := auditconfig.MakePrivateDirectory(filepath.Join(root, "native")); err != nil {
		return nil, err
	}
	if err := auditconfig.MakePrivateDirectory(filepath.Join(root, "transactions")); err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(root, "installation.lock"), []byte("PAO installation lock v1\n")); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(manifest{Version: Version, ID: id, CreatedAt: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(root, "installation.json"), raw); err != nil {
		return nil, err
	}
	if err := syncDirectory(root); err != nil {
		return nil, err
	}
	return Open(root)
}

// Open and Pending are read-only. No directory or lock is created here.
func Open(root string) (*Store, error) {
	if err := ValidatePrivatePath(root, true); err != nil {
		return nil, fmt.Errorf("installation state: %w", err)
	}
	for _, name := range []string{"runs", "native", "transactions"} {
		if err := ValidatePrivatePath(filepath.Join(root, name), true); err != nil {
			return nil, err
		}
	}
	if err := ValidatePrivatePath(filepath.Join(root, "installation.lock"), false); err != nil {
		return nil, err
	}
	var m manifest
	if err := readJSON(filepath.Join(root, "installation.json"), &m); err != nil {
		return nil, err
	}
	if m.Version != Version || !identifier.MatchString(m.ID) || m.CreatedAt.IsZero() {
		return nil, errors.New("invalid installation identity; setup is required")
	}
	return &Store{root: root, id: m.ID}, nil
}

func CheckReady(root string) error {
	s, err := Open(root)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l, err := s.Lock(ctx, false)
	if err != nil {
		return err
	}
	defer l.Close()
	pending, err := s.Pending()
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return fmt.Errorf("RECOVERY_REQUIRED: pending run %s; inspect pao recover before another launch", pending[0].ID)
	}
	return nil
}

func (s *Store) Lock(ctx context.Context, exclusive bool) (*Lease, error) {
	path := filepath.Join(s.root, "installation.lock")
	if err := ValidatePrivatePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	for {
		locked, err := tryLock(f, exclusive)
		if err != nil {
			f.Close()
			return nil, err
		}
		if locked {
			return &Lease{store: s, file: f, exclusive: exclusive}, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, errors.New("installation is busy; wait for its active operation")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (l *Lease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return errors.Join(unlock(f), f.Close())
}

func (s *Store) Pending() ([]Run, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "runs"))
	if err != nil {
		return nil, err
	}
	if len(entries) > maxRuns {
		return nil, errors.New("installation journal exceeds supported record count")
	}
	result := []Run{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || !identifier.MatchString(strings.TrimSuffix(e.Name(), ".json")) {
			return nil, errors.New("unexpected installation journal entry")
		}
		r, err := s.Read(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		if r.Status != "VERIFIED_ABSENT" {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *Store) Read(id string) (Run, error) {
	var r Run
	if !identifier.MatchString(id) {
		return r, errors.New("run must be an exact lifecycle ID")
	}
	if err := readJSON(filepath.Join(s.root, "runs", id+".json"), &r); err != nil {
		return r, err
	}
	if err := r.validate(s.id); err != nil || r.ID != id {
		return Run{}, errors.Join(err, errors.New("invalid lifecycle record identity"))
	}
	return r, nil
}

func (l *Lease) Begin(auditID, name, endpoint, image, dockerPath, dockerDigest string) (Run, error) {
	var r Run
	if l == nil || l.file == nil || !l.exclusive {
		return r, errors.New("exclusive installation lease required")
	}
	pending, err := l.store.Pending()
	if err != nil {
		return r, err
	}
	if len(pending) != 0 {
		return r, fmt.Errorf("RECOVERY_REQUIRED: pending run %s", pending[0].ID)
	}
	id, err := randomID()
	if err != nil {
		return r, err
	}
	now := time.Now().UTC()
	r = Run{Version: RunVersion, ID: id, InstallationID: l.store.id, AuditID: auditID, ContainerName: name, Endpoint: endpoint, RuntimeImage: image, DockerPath: dockerPath, DockerSHA256: dockerDigest, Status: "PENDING", CreatedAt: now, UpdatedAt: now}
	if err := r.validate(l.store.id); err != nil {
		return Run{}, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return Run{}, err
	}
	if err := replaceJSON(filepath.Join(l.store.root, "runs", id+".json"), raw); err != nil {
		return Run{}, err
	}
	return r, nil
}

// Update only advances lifecycle state, retaining identity and verified evidence.
func (l *Lease) Update(r Run, containerID, status string) (Run, error) {
	if l == nil || l.file == nil || !l.exclusive {
		return r, errors.New("exclusive installation lease required")
	}
	previous, err := l.store.Read(r.ID)
	if err != nil {
		return r, err
	}
	if previous != r || previous.Status == "VERIFIED_ABSENT" {
		return r, errors.New("lifecycle changed or already completed")
	}
	if previous.ContainerID != "" && containerID != previous.ContainerID {
		return r, errors.New("container identity cannot change")
	}
	r.ContainerID, r.Status, r.UpdatedAt = containerID, status, time.Now().UTC()
	if err := r.validate(l.store.id); err != nil {
		return previous, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return previous, err
	}
	if err := replaceJSON(filepath.Join(l.store.root, "runs", r.ID+".json"), raw); err != nil {
		return previous, err
	}
	return r, nil
}

func (r Run) validate(id string) error {
	if r.Version != RunVersion || !identifier.MatchString(r.ID) || r.InstallationID != id || !safeName.MatchString(r.AuditID) || !safeName.MatchString(r.ContainerName) || !digest.MatchString(r.RuntimeImage) || !digest.MatchString(r.DockerSHA256) || !filepath.IsAbs(r.DockerPath) || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return errors.New("invalid lifecycle record")
	}
	if r.Endpoint != "npipe:////./pipe/dockerDesktopLinuxEngine" && (!strings.HasPrefix(r.Endpoint, "unix:///") || !strings.HasSuffix(r.Endpoint, "/.docker/desktop/docker.sock")) {
		return errors.New("unsupported journal Docker endpoint")
	}
	if strings.ContainsAny(r.Endpoint+r.DockerPath, "\x00\r\n") {
		return errors.New("invalid lifecycle path")
	}
	if r.ContainerID != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.ContainerID) {
		return errors.New("invalid full container ID")
	}
	if r.Status != "PENDING" && r.Status != "OBSERVED" && r.Status != "VERIFIED_ABSENT" {
		return errors.New("invalid lifecycle status")
	}
	return nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func readJSON(path string, value any) error {
	if err := ValidatePrivatePath(path, false); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return err
	}
	return strictjson.Decode(raw, value, maxRecordBytes)
}

func writeNew(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}

func replaceJSON(path string, raw []byte) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	// Orphaned transactions are harmless: a container cannot launch before the
	// final pending record is durable. Never interpret a partial transaction.
	temp := filepath.Join(filepath.Dir(filepath.Dir(path)), "transactions", filepath.Base(path)+".next-"+id)
	if err := writeNew(temp, raw); err != nil {
		return err
	}
	defer os.Remove(temp)
	if err := replaceFile(temp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
