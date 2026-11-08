package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type downloader struct{ client *http.Client }

func newDownloader() *downloader {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &downloader{client: &http.Client{Transport: transport, Timeout: 15 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("download redirect limit")
		}
		u := req.URL
		if u.Scheme != "https" || u.User != nil || u.Port() != "" {
			return errors.New("unsafe download redirect")
		}
		switch u.Hostname() {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "files.pythonhosted.org", "deb.debian.org", "snapshot.debian.org", "storage.googleapis.com", "ghcr.io", "pkg-containers.githubusercontent.com":
		default:
			return errors.New("unadmitted download redirect host")
		}
		// An anonymous registry token never crosses origin boundaries.
		if len(via) > 0 && via[0].URL.Hostname() != u.Hostname() {
			req.Header.Del("Authorization")
		}
		return nil
	}}}
}

func (d *downloader) get(ctx context.Context, raw string, limit int64, headers map[string]string) ([]byte, http.Header, error) {
	if err := publicURL(raw); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "PAO-setup/0.3")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r, err := d.client.Do(req)
	if err != nil {
		return nil, nil, errors.New("public metadata request failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, nil, fmt.Errorf("public metadata HTTP %d", r.StatusCode)
	}
	if r.ContentLength > limit {
		return nil, nil, errors.New("metadata size limit")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, nil, errors.New("metadata size or read failure")
	}
	return b, r.Header, nil
}

func (d *downloader) fetch(ctx context.Context, a Artifact, cache string, headers map[string]string) (string, error) {
	if err := publicURL(a.URL); err != nil {
		return "", err
	}
	if a.Bytes <= 0 || a.Bytes > 512<<20 || !digestPattern.MatchString(a.SHA256) {
		return "", errors.New("immutable bounded artifact required")
	}
	dest := filepath.Join(cache, a.SHA256+"-"+a.Filename)
	if h, err := hashFile(dest, a.Bytes); err == nil {
		if h == a.SHA256 {
			return dest, nil
		}
		return "", errors.New("cached artifact hash mismatch; preserved for review")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		partial, err := os.CreateTemp(cache, "download-*.partial")
		if err != nil {
			return "", err
		}
		partialPath := partial.Name()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
		if err != nil {
			partial.Close()
			return "", err
		}
		req.Header.Set("User-Agent", "PAO-setup/0.3")
		req.Header.Set("Accept-Encoding", "identity")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		r, err := d.client.Do(req)
		if err != nil {
			partial.Close()
			if attempt == 0 {
				continue
			}
			return "", errors.New("download transport failed; partial attempt retained")
		}
		if r.StatusCode != 200 || r.ContentLength > a.Bytes {
			r.Body.Close()
			partial.Close()
			return "", fmt.Errorf("artifact HTTP status/size refused (%d)", r.StatusCode)
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(partial, h), io.LimitReader(r.Body, a.Bytes+1))
		r.Body.Close()
		syncErr := partial.Sync()
		closeErr := partial.Close()
		if copyErr != nil {
			if attempt == 0 {
				continue
			}
			return "", errors.New("download interrupted; partial attempts retained")
		}
		if err := errors.Join(syncErr, closeErr); err != nil {
			return "", err
		}
		if n != a.Bytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return "", errors.New("download bytes or SHA-256 differ from approved artifact")
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			return "", errors.New("download destination already exists")
		}
		if err := os.Rename(partialPath, dest); err != nil {
			return "", err
		}
		return dest, nil
	}
	return "", errors.New("download not completed")
}

func safeMetadataURL(base, member string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || !safeRelative(member) || strings.ContainsAny(member, "?#") {
		return "", errors.New("unsafe metadata download member")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + member
	return u.String(), publicURL(u.String())
}
