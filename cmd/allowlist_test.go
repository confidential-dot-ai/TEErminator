package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// canonicalDoc is a served canonical-allowlist document whose exact byte string
// is what a stamp digest would be taken over.
var canonicalDoc = []byte(`{"workloads":{"api":{"containers":[]}},"schema":"c8s.allowlist/v1"}`)

func TestResolveOutputPath(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(existing, canonicalDoc, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "new.json")
	pinned := config.Remote{Local: "127.0.0.1:8080", AllowlistPath: existing}

	t.Run("missing --output", func(t *testing.T) {
		if _, err := resolveOutputPath("", &config.Remote{}, false); err == nil {
			t.Fatal("want an error naming --output")
		}
	})

	t.Run("new path is accepted, absolute", func(t *testing.T) {
		got, err := resolveOutputPath(fresh, &config.Remote{}, false)
		if err != nil || got != fresh {
			t.Fatalf("resolveOutputPath = (%q, %v), want %q", got, err, fresh)
		}
	})

	t.Run("existing file is refused without --force", func(t *testing.T) {
		_, err := resolveOutputPath(existing, &config.Remote{}, false)
		if err == nil || !strings.Contains(err.Error(), "--force") {
			t.Fatalf("want a refusal naming --force, got %v", err)
		}
	})

	t.Run("the remote's current pin is named in the refusal", func(t *testing.T) {
		_, err := resolveOutputPath(existing, &pinned, false)
		if err == nil || !strings.Contains(err.Error(), "currently pins") {
			t.Fatalf("want the refusal to say the file is the live pin, got %v", err)
		}
		if !strings.Contains(err.Error(), "127.0.0.1:8080") {
			t.Errorf("refusal %q does not name the remote", err)
		}
	})

	t.Run("--force overwrites, pin or not", func(t *testing.T) {
		if _, err := resolveOutputPath(existing, &pinned, true); err != nil {
			t.Fatal(err)
		}
	})
}

// TestWriteAllowlistFileIsVerbatimAndAtomic: the digest was taken over the
// received bytes, so the file must hold exactly them, and a completed write
// must leave nothing but that file in the directory.
func TestWriteAllowlistFileIsVerbatimAndAtomic(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "allowlist.json")

	if err := writeAllowlistFile(out, canonicalDoc); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, canonicalDoc) {
		t.Fatalf("file holds %s, want the served bytes %s", got, canonicalDoc)
	}
	// A JSON round trip of the same document is a different byte string: this
	// is what the verbatim comparison above is guarding against.
	var round map[string]any
	if err := json.Unmarshal(got, &round); err != nil {
		t.Fatal(err)
	}
	if reencoded, err := json.Marshal(round); err != nil {
		t.Fatal(err)
	} else if bytes.Equal(reencoded, canonicalDoc) {
		t.Fatal("fixture document survives a JSON round trip unchanged, so this test cannot detect a re-encoding")
	}
	assertOnly(t, dir, "allowlist.json")

	// Overwriting in place (the --force path) replaces the file and again
	// leaves no temporary behind.
	replacement := []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)
	if err := writeAllowlistFile(out, replacement); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("overwrite left %s (%v), want %s", got, err, replacement)
	}
	assertOnly(t, dir, "allowlist.json")
}

func TestWriteAllowlistFileLeavesNothingOnFailure(t *testing.T) {
	dir := t.TempDir()
	// A destination directory that does not exist: the temporary file cannot be
	// created there, and nothing is left anywhere.
	if err := writeAllowlistFile(filepath.Join(dir, "missing", "allowlist.json"), canonicalDoc); err == nil {
		t.Fatal("want an error writing into a missing directory")
	}
	assertOnly(t, dir)
}

// TestAllowlistFetchWritesNothingWhenTheCheckCannotPass drives the command end
// to end against a front door that cannot attest. The write happens strictly
// after the check, so a fetch that does not reach a matching document must
// leave the output directory exactly as it found it — no partial file, no
// temporary file — and must fail the command (a non-zero exit).
func TestAllowlistFetchWritesNothingWhenTheCheckCannotPass(t *testing.T) {
	// Serves an allowlist but no attestation: the bytes exist, nothing vouches
	// for them.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(canonicalDoc)
	}))
	defer ts.Close()

	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	writeConfig(t, config.Config{Remotes: []config.Remote{{
		Local:        "127.0.0.1:8080",
		Remote:       ts.URL,
		Mode:         config.AttestEndpoint,
		Measurements: []string{"a1"},
	}}})

	outDir := t.TempDir()
	out := filepath.Join(outDir, "allowlist.json")
	cmd := newAllowlistCmd(DefaultName)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"fetch", "127.0.0.1:8080", "-o", out, "--timeout", "5s"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("want a non-zero exit: nothing attested the served document")
	}
	assertOnly(t, outDir)
}

func TestAllowlistFetchUnknownRemote(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cmd := newAllowlistCmd(DefaultName)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"fetch", "nope", "-o", filepath.Join(t.TempDir(), "a.json")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no remote found") {
		t.Fatalf("want an unknown-remote error, got %v", err)
	}
}

// writeConfig stores cfg where config.Load will find it.
func writeConfig(t *testing.T, cfg config.Config) {
	t.Helper()
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "teerminator")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertOnly requires dir to contain exactly the named entries — the check that
// no temporary file survived.
func assertOnly(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s contains %v, want exactly %v", dir, got, want)
	}
}
