package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// caCertPEM makes a distinct self-signed CA with the given common name.
func caCertPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// mustAddCert stores a cert the way `certs add` does, computing the
// fingerprint from the PEM, and returns the stored entry.
func mustAddCert(t *testing.T, cfg *Config, commonName, pemData string) Cert {
	t.Helper()
	fp, err := CertFingerprint([]byte(pemData))
	if err != nil {
		t.Fatal(err)
	}
	cert := Cert{Fingerprint: fp, CommonName: commonName, PEM: pemData}
	if err := cfg.AddCert(cert); err != nil {
		t.Fatalf("AddCert(%q) = %v, want nil", commonName, err)
	}
	return cert
}

// TestAddCertSameCommonName: every c8s cluster's mesh CA shares CN=c8s Mesh CA,
// so two distinct certs with the same CN must coexist; only an exact duplicate
// (same fingerprint) is rejected.
func TestAddCertSameCommonName(t *testing.T) {
	const cn = "c8s Mesh CA"
	cfg := &Config{}
	a := mustAddCert(t, cfg, cn, caCertPEM(t, cn))
	mustAddCert(t, cfg, cn, caCertPEM(t, cn))
	if len(cfg.Certs) != 2 {
		t.Fatalf("stored certs = %d, want 2", len(cfg.Certs))
	}

	if err := cfg.AddCert(a); err == nil {
		t.Error("AddCert(duplicate) = nil, want error")
	}
	// The duplicate check keys on the certificate, not the CN field.
	dup := a
	dup.CommonName = "renamed"
	if err := cfg.AddCert(dup); err == nil {
		t.Error("AddCert(duplicate under other name) = nil, want error")
	}
}

// TestAddCertComputesFingerprint: an entry stored without a fingerprint (e.g.
// by an embedding caller) gets one computed from the PEM.
func TestAddCertComputesFingerprint(t *testing.T) {
	cfg := &Config{}
	pemData := caCertPEM(t, "anchor")
	if err := cfg.AddCert(Cert{CommonName: "anchor", PEM: pemData}); err != nil {
		t.Fatal(err)
	}
	want, err := CertFingerprint([]byte(pemData))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Certs[0].Fingerprint; got != want {
		t.Errorf("stored fingerprint = %q, want %q", got, want)
	}
}

func TestFindCertsAndRemove(t *testing.T) {
	const cn = "c8s Mesh CA"
	cfg := &Config{}
	a := mustAddCert(t, cfg, cn, caCertPEM(t, cn))
	b := mustAddCert(t, cfg, cn, caCertPEM(t, cn))
	other := mustAddCert(t, cfg, "other CA", caCertPEM(t, "other CA"))

	if got := cfg.FindCerts(a.Fingerprint); len(got) != 1 || got[0].Fingerprint != a.Fingerprint {
		t.Errorf("FindCerts(full fingerprint) = %d certs, want exactly a", len(got))
	}
	prefix := a.Fingerprint[:12]
	if b.Fingerprint[:12] == prefix || other.Fingerprint[:12] == prefix {
		t.Fatal("fingerprint prefixes collide; regenerate")
	}
	if got := cfg.FindCerts(strings.ToUpper(prefix)); len(got) != 1 || got[0].Fingerprint != a.Fingerprint {
		t.Errorf("FindCerts(uppercase prefix) = %d certs, want exactly a", len(got))
	}
	if got := cfg.FindCerts(cn); len(got) != 2 {
		t.Errorf("FindCerts(shared CN) = %d certs, want 2", len(got))
	}
	if got := cfg.FindCerts("other CA"); len(got) != 1 || got[0].Fingerprint != other.Fingerprint {
		t.Errorf("FindCerts(unique CN) = %d certs, want exactly other", len(got))
	}
	if got := cfg.FindCerts("nope"); got != nil {
		t.Errorf("FindCerts(unknown) = %v, want nil", got)
	}

	if !cfg.RemoveCert(a.Fingerprint) {
		t.Fatal("RemoveCert(a) = false, want true")
	}
	if cfg.RemoveCert(a.Fingerprint) {
		t.Error("RemoveCert(a) twice = true, want false")
	}
	if len(cfg.Certs) != 2 {
		t.Fatalf("stored certs after removal = %d, want 2", len(cfg.Certs))
	}
}

// TestLoadMigratesCertFingerprints: a config written by the CN-keyed store has
// certs without fingerprints; Load must fill them in from the PEM.
func TestLoadMigratesCertFingerprints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "teerminator"), 0o700); err != nil {
		t.Fatal(err)
	}
	pemData := caCertPEM(t, "c8s Mesh CA")
	raw, err := json.Marshal(map[string]any{
		"remotes": []any{},
		"certs": []map[string]string{
			{"common_name": "c8s Mesh CA", "pem": pemData},
			{"common_name": "broken", "pem": "not a pem"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "teerminator", "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certs) != 2 {
		t.Fatalf("certs = %d, want 2", len(cfg.Certs))
	}
	want, err := CertFingerprint([]byte(pemData))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Certs[0].Fingerprint; got != want {
		t.Errorf("migrated fingerprint = %q, want %q", got, want)
	}
	// An unparseable stored PEM must not make the config unloadable; its
	// entry stays, fingerprintless, removable by CN.
	if got := cfg.Certs[1].Fingerprint; got != "" {
		t.Errorf("fingerprint of unparseable cert = %q, want empty", got)
	}
	if got := cfg.FindCerts("broken"); len(got) != 1 {
		t.Errorf("FindCerts(broken) = %d certs, want 1", len(got))
	}
}
