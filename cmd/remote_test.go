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
	const (
		manifest = "/tmp/manifest.json"
		rtmr3    = "deadbeef"
		tcb      = "3,0,8,209"
	)
	tdxTCB := []string{"UpToDate"}
	routes := []string{strings.Repeat("ab", 32)}
	keys := []string{"operator.pub"}
	for _, tc := range []struct {
		name                 string
		mode                 config.AttestMode
		manifest, rtmr3, tcb string
		tdxTCB, routes, keys []string
		wantFlag             string
	}{
		{"attest-lb accepts every pin", config.AttestEndpoint, manifest, rtmr3, tcb, tdxTCB, routes, keys, ""},
		{"no mode, no pins", config.AttestNone, "", "", "", nil, nil, nil, ""},
		{"no mode rejects the image manifest", config.AttestNone, manifest, "", "", nil, nil, nil, "--image-manifest"},
		{"no mode rejects the rtmr3 pin", config.AttestNone, "", rtmr3, "", nil, nil, nil, "--expected-rtmr3"},
		{"no mode rejects the tcb floor", config.AttestNone, "", "", tcb, nil, nil, nil, "--min-tcb"},
		{"no mode rejects the tdx tcb status", config.AttestNone, "", "", "", tdxTCB, nil, nil, "--tdx-tcb-status"},
		{"cds-cert rejects the image manifest", config.AttestCDSCert, manifest, "", "", nil, nil, nil, "--image-manifest"},
		{"cds-cert rejects the rtmr3 pin", config.AttestCDSCert, "", rtmr3, "", nil, nil, nil, "--expected-rtmr3"},
		{"cds-cert rejects the tcb floor", config.AttestCDSCert, "", "", tcb, nil, nil, nil, "--min-tcb"},
		{"cds-cert rejects the tdx tcb status", config.AttestCDSCert, "", "", "", tdxTCB, nil, nil, "--tdx-tcb-status"},
		{"no mode rejects the route digest", config.AttestNone, "", "", "", nil, routes, nil, "--route-digest"},
		{"cds-cert rejects the route digest", config.AttestCDSCert, "", "", "", nil, routes, nil, "--route-digest"},
		{"no mode rejects the route operator key", config.AttestNone, "", "", "", nil, nil, keys, "--route-operator-key"},
		{"cds-cert rejects the route operator key", config.AttestCDSCert, "", "", "", nil, nil, keys, "--route-operator-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePinModes(tc.mode, tc.manifest, tc.rtmr3, tc.tcb, tc.tdxTCB, tc.routes, tc.keys)
			if tc.wantFlag == "" {
				if err != nil {
					t.Fatalf("validatePinModes = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantFlag) {
				t.Fatalf("validatePinModes = %v, want an error naming %s", err, tc.wantFlag)
			}
		})
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
	got, err := readRouteOperatorKeys([]string{two, one})
	if err != nil {
		t.Fatalf("readRouteOperatorKeys() = %v", err)
	}
	if strings.Join(got, "") != strings.Join(pubs, "") {
		t.Errorf("readRouteOperatorKeys() = %q, want %q", got, pubs)
	}
	for _, bad := range []string{write("private.pem", block("PRIVATE KEY", priv)), filepath.Join(dir, "missing.pub")} {
		if _, err := readRouteOperatorKeys([]string{bad}); err == nil {
			t.Errorf("readRouteOperatorKeys(%s) = nil, want error", filepath.Base(bad))
		}
	}
}
