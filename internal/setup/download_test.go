package setup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type downloadTransport func(*http.Request) (*http.Response, error)

func (f downloadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenDownloadBody struct {
	prefix *strings.Reader
	closed bool
}

func (b *brokenDownloadBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	return 0, io.ErrUnexpectedEOF
}
func (b *brokenDownloadBody) Close() error { b.closed = true; return nil }

func TestInterruptedDownloadRetainsAttemptsAndPublishesOnlyVerifiedBytes(t *testing.T) {
	const payload = "synthetic pinned artifact bytes"
	for _, failBoth := range []bool{false, true} {
		name := "retry_succeeds"
		if failBoth {
			name = "both_attempts_interrupted"
		}
		t.Run(name, func(t *testing.T) {
			cache := t.TempDir()
			a := Artifact{URL: "https://github.com/example/fixture", Filename: "fixture.bin", Bytes: int64(len(payload)), SHA256: hashBytes([]byte(payload))}
			dest := filepath.Join(cache, a.SHA256+"-"+a.Filename)
			calls := 0
			var interrupted []*brokenDownloadBody
			d := &downloader{client: &http.Client{Transport: downloadTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "identity" {
					t.Fatal("unexpected download request")
				}
				if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("an incomplete attempt was published before verification")
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(payload))
				if calls == 1 || failBoth {
					broken := &brokenDownloadBody{prefix: strings.NewReader(payload[:8])}
					interrupted = append(interrupted, broken)
					body = broken
				}
				return &http.Response{StatusCode: http.StatusOK, ContentLength: a.Bytes, Body: body, Header: http.Header{}, Request: r}, nil
			})}}
			path, err := d.fetch(context.Background(), a, cache, nil)
			if calls != 2 {
				t.Fatalf("expected bounded retry, got %d requests", calls)
			}
			for _, body := range interrupted {
				if !body.closed {
					t.Fatal("interrupted response was not closed")
				}
			}
			partials, globErr := filepath.Glob(filepath.Join(cache, "download-*.partial"))
			if globErr != nil || len(partials) != len(interrupted) {
				t.Fatalf("interrupted attempts were removed or replaced: %v %v", partials, globErr)
			}
			for _, partial := range partials {
				got, readErr := os.ReadFile(partial)
				if readErr != nil || string(got) != payload[:8] {
					t.Fatal("partial evidence changed")
				}
			}
			if failBoth {
				if err == nil || path != "" {
					t.Fatal("interrupted download was admitted")
				}
				if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("interrupted bytes entered the completed cache")
				}
				return
			}
			if err != nil || path != dest {
				t.Fatalf("verified retry failed: %s %v", path, err)
			}
			got, err := os.ReadFile(dest)
			if err != nil || string(got) != payload {
				t.Fatal("completed download differs from the pinned bytes")
			}
			// A later invocation must hash the completed cache without networking.
			d.client.Transport = downloadTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("verified completed download was fetched again")
				return nil, errors.New("unexpected request")
			})
			if next, err := d.fetch(context.Background(), a, cache, nil); err != nil || next != dest {
				t.Fatalf("completed cache was not resumable: %v", err)
			}
		})
	}
}
