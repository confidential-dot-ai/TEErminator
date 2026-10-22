package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
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
	// An all-zero floor gates nothing (every component is >= 0) but a non-nil
	// one reads as "a floor is set" at enforcement time, which rejects every
	// TDX remote as a cross-platform pin. It must come back as no floor.
	if got, err := parseMinTCBFlag("0,0,0,0"); err != nil || got != nil {
		t.Errorf("all-zero --min-tcb = (%v, %v), want (nil, nil)", got, err)
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

// TestValidatePinModes covers the pin/mode guard: a platform pin stored on a
// remote no verifier will ever read looks configured and silently protects
// nothing, so it is refused at add time rather than at some later verification
// that never runs.
func TestValidatePinModes(t *testing.T) {
	flags := []string{"--image-manifest", "--expected-rtmr3", "--operator-pkey", "--rtmr", "--init-data", "--sandbox-id",
		"--min-tcb", "--tdx-tcb-status", "--route-digest", "--route-operator-key", "--routes-floor",
		"--pin-policy", "--trust-operator", "--trust-operator-key"}
	all := make([]pinFlag, len(flags))
	for i, f := range flags {
		all[i] = pinFlag{f, "x"}
	}
	if err := validatePinModes(config.AttestEndpoint, all); err != nil {
		t.Fatalf("validatePinModes(attest-lb, every pin) = %v, want nil", err)
	}
	if err := validatePinModes(config.AttestNone, []pinFlag{{"--min-tcb", ""}}); err != nil {
		t.Fatalf("validatePinModes(no mode, no pins) = %v, want nil", err)
	}
	for _, mode := range []config.AttestMode{config.AttestNone, config.AttestCDSCert} {
		for _, f := range flags {
			err := validatePinModes(mode, []pinFlag{{f, "x"}})
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("validatePinModes(%q, %s) = %v, want an error naming %s", mode, f, err, f)
			}
		}
	}
}

// TestValidateRTMR3Flag covers the copy-paste allowance: register pins are
// lifted out of terminal output, so surrounding whitespace is a typing artefact
// rather than a different value. The value stored is the trimmed one, and
// everything else stays as strict as the manifest parser.
func TestValidateRTMR3Flag(t *testing.T) {
	pin := strings.Repeat("4d", 48)
	for _, in := range []string{pin, " " + pin, pin + "\n", "\t" + pin + "  \n"} {
		got, err := validateRTMR3Flag(in)
		if err != nil {
			t.Fatalf("validateRTMR3Flag(%q) = %v", in, err)
		}
		if got != pin {
			t.Errorf("validateRTMR3Flag(%q) stored %q, want the trimmed pin", in, got)
		}
	}
	if got, err := validateRTMR3Flag("   "); err != nil || got != "" {
		t.Errorf("blank --expected-rtmr3 = (%q, %v), want no pin", got, err)
	}
	for _, bad := range []string{"aabb", strings.ToUpper(pin), strings.Repeat("zz", 48), "4d 4d"} {
		if _, err := validateRTMR3Flag(bad); err == nil {
			t.Errorf("validateRTMR3Flag(%q) accepted", bad)
		}
	}
}

// TestRemoteAddBlankRTMR3 checks that a whitespace-only --expected-rtmr3 is
// judged as the empty value it is stored as, not as an RTMR[3] seed.
func TestRemoteAddBlankRTMR3(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	body := `{"mrtd":"` + strings.Repeat("1a", 48) + `","rtmr1":"` + strings.Repeat("2b", 48) + `","rtmr2":"` + strings.Repeat("3c", 48) + `"}`
	if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newRemoteAddCmd("teerm")
	cmd.SetArgs([]string{"127.0.0.1:8080", "https://lb.example", "--mode", "attest-lb", "--image-manifest", manifest,
		"--expected-rtmr3", "  ", "--pin-policy", "sha256:" + strings.Repeat("ab", 32)})
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "require an RTMR[3] seed") {
		t.Errorf("remote add with a blank --expected-rtmr3 = %v, want the missing seed error", err)
	}
}

// TestReadRouteOperatorKeys checks that --route-operator-key stores one PEM
// block per key, read from every file, and refuses anything but public keys.
func TestReadRouteOperatorKeys(t *testing.T) {
	dir := t.TempDir()
	block := func(typ string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
	}
	var pubs []string
	var priv []byte
	for range 3 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, block("PUBLIC KEY", der))
		if priv, err = x509.MarshalPKCS8PrivateKey(k); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	two := write("two.pub", pubs[0]+pubs[1])
	one := write("one.pub", pubs[2])
	got, err := readOperatorKeys("--route-operator-key", []string{two, one})
	if err != nil {
		t.Fatalf("readOperatorKeys() = %v", err)
	}
	if strings.Join(got, "") != strings.Join(pubs, "") {
		t.Errorf("readOperatorKeys() = %q, want %q", got, pubs)
	}
	for _, bad := range []string{write("private.pem", block("PRIVATE KEY", priv)), filepath.Join(dir, "missing.pub")} {
		if _, err := readOperatorKeys("--route-operator-key", []string{bad}); err == nil {
			t.Errorf("readOperatorKeys(%s) = nil, want error", filepath.Base(bad))
		}
	}
}

func TestFrontDoorWorkload(t *testing.T) {
	tests := []struct {
		name, workloads, want, wantErr string
	}{
		{"one front door", `"api":{},"c8s-router-fb21f5cac23c":{}`, "c8s-router-fb21f5cac23c", ""},
		{"none", `"api":{},"c8s-router-nginx":{}`, "", "no c8s-router-* front-door entry"},
		{"ambiguous", `"c8s-router-000000000001":{},"c8s-router-000000000002":{}`, "", "c8s-router-000000000001, c8s-router-000000000002"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "allowlist.json")
			doc := `{"schema":"` + verifier.AllowlistSchema + `","workloads":{` + tc.workloads + `}}`
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := frontDoorWorkload(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("frontDoorWorkload = (%q, %v), want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("frontDoorWorkload = (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
}
