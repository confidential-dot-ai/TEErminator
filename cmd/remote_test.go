package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func TestDefaultServerName(t *testing.T) {
	tests := []struct {
		name          string
		remoteURL     string
		explicit      string
		want          string
		wantDefaulted bool
	}{
		{"IP remote, no override", "https://100.107.26.45:32123/", "", defaultC8sServerName, true},
		{"IPv6 remote, no override", "https://[2001:db8::1]:443/", "", defaultC8sServerName, true},
		{"DNS remote, no override", "https://api.example.com/v1/", "", "", false},
		{"IP remote, explicit override wins", "https://100.107.26.45:32123/", "lb.internal", "lb.internal", false},
		{"explicit IP override disables the default", "https://100.107.26.45:32123/", "100.107.26.45", "100.107.26.45", false},
		{"unparseable URL", "://bad", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, defaulted := defaultServerName(tc.remoteURL, tc.explicit)
			if got != tc.want || defaulted != tc.wantDefaulted {
				t.Errorf("defaultServerName(%q, %q) = (%q, %v), want (%q, %v)",
					tc.remoteURL, tc.explicit, got, defaulted, tc.want, tc.wantDefaulted)
			}
		})
	}
}

func TestParseMinTCBFlag(t *testing.T) {
	got, err := parseMinTCBFlag("3, 0,8,209")
	if err != nil {
		t.Fatal(err)
	}
	if want := (config.TCBFloor{Bootloader: 3, TEE: 0, SNP: 8, Microcode: 209}); *got != want {
		t.Errorf("parseMinTCBFlag = %+v, want %+v", *got, want)
	}
	if got, err := parseMinTCBFlag(""); err != nil || got != nil {
		t.Errorf("empty --min-tcb = (%v, %v), want (nil, nil)", got, err)
	}
	for _, bad := range []string{"3,0,8", "3,0,8,209,1", "3,0,8,256", "a,b,c,d", "3,,8,209"} {
		if _, err := parseMinTCBFlag(bad); err == nil {
			t.Errorf("parseMinTCBFlag(%q) accepted", bad)
		}
	}
}

func TestValidateImageManifestFlag(t *testing.T) {
	if stored, err := validateImageManifestFlag(""); err != nil || stored != "" {
		t.Errorf("empty flag = (%q, %v), want no-op", stored, err)
	}

	dir := t.TempDir()
	valid := filepath.Join(dir, "manifest.json")
	body := `{"mrtd":"` + strings.Repeat("1a", 48) + `","rtmr1":"` + strings.Repeat("2b", 48) + `","rtmr2":"` + strings.Repeat("3c", 48) + `"}`
	if err := os.WriteFile(valid, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stored, err := validateImageManifestFlag(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(stored) {
		t.Errorf("stored path %q is not absolute", stored)
	}

	if _, err := validateImageManifestFlag(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("missing manifest accepted")
	}
	partial := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(partial, []byte(`{"mrtd":"`+strings.Repeat("1a", 48)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateImageManifestFlag(partial); err == nil || !strings.Contains(err.Error(), `missing "rtmr1"`) {
		t.Errorf("partial manifest error = %v", err)
	}
}
