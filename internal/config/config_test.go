package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAttestMode(t *testing.T) {
	for _, tc := range []struct {
		in         string
		mode       AttestMode
		normalized bool
		ok         bool
	}{
		{"", AttestNone, false, true},
		{"attest-lb", AttestEndpoint, false, true},
		{"attest", AttestEndpoint, true, true}, // legacy spelling
		{"cds-cert", AttestCDSCert, false, true},
		{"bogus", "", false, false},
	} {
		mode, normalized, ok := ParseAttestMode(tc.in)
		if mode != tc.mode || normalized != tc.normalized || ok != tc.ok {
			t.Errorf("ParseAttestMode(%q) = (%q, %v, %v), want (%q, %v, %v)",
				tc.in, mode, normalized, ok, tc.mode, tc.normalized, tc.ok)
		}
	}
}

// TestLoadNormalizesLegacyAttestMode: configs written before the endpoint split
// carry mode "attest"; Load must surface them as "attest-lb".
func TestLoadNormalizesLegacyAttestMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "teerminator"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"remotes":[{"local":"127.0.0.1:8080","remote":"https://lb.example/","auth":"None","status":"Unknown","mode":"attest"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "teerminator", "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Remotes) != 1 {
		t.Fatalf("remotes = %d, want 1", len(cfg.Remotes))
	}
	if got := cfg.Remotes[0].Mode; got != AttestEndpoint {
		t.Fatalf("mode = %q, want %q", got, AttestEndpoint)
	}
}
