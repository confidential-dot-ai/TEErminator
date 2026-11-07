package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// RunAllowlistCommandTests drives `allowlist fetch` through run against the
// attest-lb fixture: the remote pins old.json, the cluster stamps and serves a
// replacement document.
func RunAllowlistCommandTests(t *testing.T, run func(context.Context, ...string) error) {
	old := defaultAllowlistRaw
	replacement := append(append([]byte(nil), old...), '\n')
	cases := []struct {
		name, workload, want string
		inPlace, force, pin  bool
	}{
		{name: "pin to a new path", pin: true},
		{name: "pin in place", inPlace: true, force: true, pin: true},
		{name: "without --pin the old pin applies", inPlace: true, force: true, want: "pinned allowlist"},
		{name: "--pin keeps the workload check", workload: "other", pin: true, want: "pinned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			dir := t.TempDir()
			pinned, out := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
			if tc.inPlace {
				out = pinned
			}
			if err := os.WriteFile(pinned, old, 0o600); err != nil {
				t.Fatal(err)
			}
			stubEvidence(t)
			f := newLBFixture(t, fixtureOpts{allowlistRaw: replacement})
			ts := f.newServer(t, bundleSpec{allowlist: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(replacement)
			}})
			workload := "api"
			if tc.workload != "" {
				workload = tc.workload
			}
			remote := config.Remote{Local: "127.0.0.1:8080", Remote: ts.URL, Mode: config.AttestEndpoint,
				Measurements: []string{launchDigestHex("a1")}, WorkloadName: workload, AllowlistPath: pinned,
				RouteDigests: []string{hex.EncodeToString(fixtureRouteDigest[:])}}
			if err := (&config.Config{Remotes: []config.Remote{remote}}).Save(); err != nil {
				t.Fatal(err)
			}

			args := []string{"allowlist", "fetch", remote.Local, "-o", out, "--timeout", "5s"}
			if tc.pin {
				args = append(args, "--pin")
			}
			if tc.force {
				args = append(args, "--force")
			}
			err := run(context.Background(), args...)

			wantPin, wantBytes := out, replacement
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("fetch = %v, want %q", err, tc.want)
				}
				wantPin, wantBytes = pinned, old
			} else if err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(wantPin); err != nil || !bytes.Equal(got, wantBytes) {
				t.Fatalf("%s = %q (%v), want %q", wantPin, got, err, wantBytes)
			}
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Remotes[0].AllowlistPath; got != wantPin {
				t.Fatalf("allowlist pin = %s, want %s", got, wantPin)
			}
		})
	}
}
