package release

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata holds confidential-dot-ai/confidential-inference v0.15.15's
// signed assets and the Sigstore public-good trusted root.
var signed = Source{Owner: "confidential-dot-ai", Repo: "confidential-inference", Tag: "v0.15.15"}

func serve(t *testing.T, override map[string][]byte) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if body, ok := override[name]; ok {
			_, _ = w.Write(body)
			return
		}
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func trustedRoot(t *testing.T) root.TrustedMaterial {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath("testdata/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestFetch(t *testing.T) {
	ts := serve(t, nil)
	dir := filepath.Join(t.TempDir(), "pins")
	f := &Fetcher{Client: ts.Client(), BaseURL: ts.URL, Trusted: trustedRoot(t)}
	pins, err := f.Fetch(context.Background(), signed, dir)
	if err != nil {
		t.Fatal(err)
	}
	if pins.OperatorKey != "" {
		t.Errorf("OperatorKey = %q, want none: v0.15.15 publishes no operator key", pins.OperatorKey)
	}
	for path, name := range map[string]string{pins.ImageManifest: bundleName, pins.Allowlist: "allowlist.json"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(filepath.Join("testdata", name))
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not the served bytes", path)
		}
	}
}

func TestFetchRefuses(t *testing.T) {
	allowlist, err := os.ReadFile("testdata/allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		src      Source
		override map[string][]byte
		wantErr  string
	}{
		{"other tag", Source{signed.Owner, signed.Repo, "v0.15.14"}, nil, "does not verify"},
		{"other repository", Source{signed.Owner, "confidential-inference-fork", signed.Tag}, nil, "does not verify"},
		{"changed bundle", signed, map[string][]byte{bundleName: []byte(`{"allowlist":{"path":"allowlist.json","sha256":"sha256:00"}}`)}, "does not verify"},
		{"changed allowlist", signed, map[string][]byte{"allowlist.json": append(allowlist, ' ')}, "digest sha256:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := serve(t, tc.override)
			dir := filepath.Join(t.TempDir(), "pins")
			f := &Fetcher{Client: ts.Client(), BaseURL: ts.URL, Trusted: trustedRoot(t)}
			if _, err := f.Fetch(context.Background(), tc.src, dir); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Fetch = %v, want an error containing %q", err, tc.wantErr)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Errorf("Fetch wrote %s after failing", dir)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	for _, s := range []string{
		"https://github.com/confidential-dot-ai/confidential-inference/releases/tag/v0.15.15",
		"https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.15.15/",
	} {
		if got, err := ParseURL(s); err != nil || got != signed {
			t.Errorf("ParseURL(%q) = (%v, %v), want %v", s, got, err, signed)
		}
	}
	for _, s := range []string{"v0.15.15", "http://github.com/a/b/releases/tag/v1", "https://example.com/a/b/releases/tag/v1"} {
		if _, err := ParseURL(s); err == nil {
			t.Errorf("ParseURL(%q) = nil error", s)
		}
	}
}
