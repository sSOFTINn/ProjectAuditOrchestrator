package setup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

func readBounded(path string, limit int64) ([]byte, error) {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Size() > limit {
		return nil, errors.New("input must be a bounded regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("input byte limit")
	}
	return b, nil
}

func hashFile(path string, limit int64) (string, error) {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Size() > limit {
		return "", errors.New("hash input byte/type limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n != i.Size() {
		return "", errors.New("hash input changed or exceeded limit")
	}
	after, err := f.Stat()
	if err != nil || after.Size() != i.Size() || !after.ModTime().Equal(i.ModTime()) {
		return "", errors.New("hash input changed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func privateDir(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return auditconfig.MakePrivateDirectory(path)
	} else if err != nil {
		return err
	}
	return installation.ValidatePrivatePath(path, true)
}

func privateTree(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return installation.ValidatePrivatePath(path, true)
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return errors.New("cannot create root")
	}
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		if err := privateTree(parent); err != nil {
			return err
		}
	}
	return auditconfig.MakePrivateDirectory(path)
}

func writeOnce(path string, data []byte) error {
	if err := auditconfig.CheckPath(path, true); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pao-write-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, we := f.Write(data)
	se := f.Sync()
	ce := f.Close()
	if err := errors.Join(we, se, ce); err != nil {
		return err
	}
	return publishFile(f.Name(), path)
}

// Link publishes an already closed and verified file without replacing an
// existing destination. Removing the temporary name leaves one ordinary file.
// A killed process can leave scratch bytes, but cannot poison a resume marker.
func publishFile(temporary, destination string) error {
	if err := os.Link(temporary, destination); err != nil {
		return err
	}
	return os.Remove(temporary)
}

func copyExact(source, destination, expected string, limit int64) error {
	if h, err := hashFile(destination, limit); err == nil {
		if h == expected {
			return nil
		}
		return errors.New("existing installed bytes differ; a new generation is required")
	}
	if err := auditconfig.CheckPath(destination, true); err != nil {
		return err
	}
	if err := privateTree(filepath.Dir(destination)); err != nil {
		return err
	}
	if err := auditconfig.CheckPath(source, false); err != nil {
		return err
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("copy source must be a bounded regular file")
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".pao-copy-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, limit+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return err
	}
	if n > limit || hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("copy digest or byte bound failed; destination not published")
	}
	return publishFile(out.Name(), destination)
}

// extractTGZ validates every archive member even when selecting just one file.
// Links, devices, duplicates, case aliases and expanded-size bombs are refused.
func extractTGZ(ctx context.Context, archive, root, selected string, maxBytes int64) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	bounded := &limitedRead{r: gz, left: maxBytes + (16 << 20)}
	tr := tar.NewReader(bounded)
	seen := map[string]bool{}
	count := 0
	var total int64
	found := selected == ""
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
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "" {
			continue
		}
		count++
		key := strings.ToLower(name)
		if count > 100000 || !safeRelative(name) || seen[key] {
			return errors.New("unsafe or duplicate archive member")
		}
		seen[key] = true
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return errors.New("archive links and special files are prohibited")
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Size < 0 || h.Size > maxBytes || total > maxBytes-h.Size {
			return errors.New("archive expansion byte limit")
		}
		total += h.Size
		if selected != "" && name != selected {
			continue
		}
		found = true
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := privateTree(filepath.Dir(path)); err != nil {
			return err
		}
		if err := auditconfig.CheckPath(path, true); err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, we := io.CopyN(out, tr, h.Size)
		se := out.Sync()
		ce := out.Close()
		if err := errors.Join(we, se, ce); err != nil {
			return err
		}
		if n != h.Size {
			return errors.New("truncated archive member")
		}
		if h.Mode&0111 != 0 {
			if err := os.Chmod(path, 0700); err != nil {
				return err
			}
		}
	}
	if !found {
		return fmt.Errorf("required archive member absent: %s", selected)
	}
	return nil
}

type limitedRead struct {
	r    io.Reader
	left int64
}

func (r *limitedRead) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("expanded stream byte limit")
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, e := r.r.Read(p)
	r.left -= int64(n)
	return n, e
}

type fileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func inventory(root, exclude string) ([]fileDigest, error) {
	rows := []fileDigest{}
	var total int64
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e.Type()&os.ModeSymlink != 0 {
			return errors.New("prepared inputs cannot contain links")
		}
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			return errors.New("prepared inputs must be regular")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == exclude {
			return nil
		}
		if !safeRelative(rel) {
			return errors.New("unsafe prepared path")
		}
		i, err := e.Info()
		if err != nil {
			return err
		}
		total += i.Size()
		if total > 8<<30 || len(rows) >= 100000 {
			return errors.New("prepared input resource limit")
		}
		h, err := hashFile(path, 4<<30)
		if err != nil {
			return err
		}
		rows = append(rows, fileDigest{rel, h})
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	return rows, err
}
