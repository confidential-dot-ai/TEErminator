package verifier

// Offline tests for the certificate-validity and self-signature checks in
// AttestCDSIdentity. These run before any quote handling, so a plain
// self-signed certificate (no RA-TLS extensions) exercises them: a cert that
// passes them then fails on the missing attestation extension, which is the
// signal the earlier checks accepted it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestAttestCDSIdentityRejectsExpiredCert(t *testing.T) {
	now := time.Now()
	certPEM, _ := testCert(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	_, err := AttestCDSIdentity(certPEM, CDSPolicy{})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want an expiry rejection", err)
	}
}

func TestAttestCDSIdentityRejectsNotYetValidCert(t *testing.T) {
	now := time.Now()
	certPEM, _ := testCert(t, now.Add(time.Hour), now.Add(2*time.Hour))
	_, err := AttestCDSIdentity(certPEM, CDSPolicy{})
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("error = %v, want a not-yet-valid rejection", err)
	}
}

// A certificate whose self-signature does not verify with its own key must be
// rejected: without that signature the validity window (and everything else in
// the tbs beyond the REPORTDATA-bound SPKI and claims) is attacker-writable.
func TestAttestCDSIdentityRejectsBadSelfSignature(t *testing.T) {
	now := time.Now()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate subject: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "forged cds"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	// Structurally self-signed (issuer == subject) but signed with a DIFFERENT
	// key than the one it carries — what re-wrapping a genuine SPKI in a fresh
	// certificate looks like when the attacker lacks the TEE-held private key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &subject.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	_, err = AttestCDSIdentity(certPEM, CDSPolicy{})
	if err == nil || !strings.Contains(err.Error(), "self-signature") {
		t.Fatalf("error = %v, want a self-signature rejection", err)
	}
}

// The clock is injectable: pinned inside a window that has passed in real
// time, the validity check accepts and the failure moves on to the missing
// RA-TLS extension.
func TestAttestCDSIdentityClockIsInjectable(t *testing.T) {
	base := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	certPEM, _ := testCert(t, base, base.Add(time.Hour))

	orig := timeNow
	timeNow = func() time.Time { return base.Add(30 * time.Minute) }
	defer func() { timeNow = orig }()

	_, err := AttestCDSIdentity(certPEM, CDSPolicy{})
	if err == nil || !strings.Contains(err.Error(), "no RA-TLS attestation extension") {
		t.Fatalf("error = %v, want the check after validity (missing extension), proving the injected clock was used", err)
	}
}
