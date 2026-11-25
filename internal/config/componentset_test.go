package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadChecksComponentSets(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name, mode, sets, wantErr string
	}{
		{"version", "attest-lb", `["0.43.0"]`, ""},
		{"version and digest", "attest-lb", `["0.43.0@sha256:` + digest + `"]`, ""},
		{"legacy attest spelling", "attest", `["0.43.0"]`, ""},
		{"two-part version", "attest-lb", `["0.43"]`, "is not MAJOR.MINOR.PATCH"},
		{"short digest", "attest-lb", `["0.43.0@sha256:abcd"]`, "is not sha256:<64 lowercase hex>"},
		{"uppercase digest", "attest-lb", `["0.43.0@sha256:` + strings.ToUpper(digest) + `"]`, "is not sha256:<64 lowercase hex>"},
		{"cds-cert mode", "cds-cert", `["0.43.0"]`, `component_set requires mode "attest-lb"`},
		{"no mode", "", `["0.43.0"]`, `component_set requires mode "attest-lb"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)
			if err := os.MkdirAll(filepath.Join(dir, "teerminator"), 0o700); err != nil {
				t.Fatal(err)
			}
			raw := `{"remotes":[{"local":"127.0.0.1:8080","remote":"https://lb.example/","mode":"` + tc.mode + `","component_set":` + tc.sets + `}]}`
			if err := os.WriteFile(filepath.Join(dir, "teerminator", "config.json"), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load()
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Load(%s) = %v, want error containing %q", raw, err, tc.wantErr)
			}
		})
	}
}
