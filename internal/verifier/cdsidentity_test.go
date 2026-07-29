package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// liveCDSIdentity returns the PEM of a real CDS certificate captured from the
// cluster, or skips. Set TEERMINATOR_CDS_IDENTITY_PEM to a file path.
func liveCDSIdentity(t *testing.T) []byte {
	t.Helper()
	path := os.Getenv("TEERMINATOR_CDS_IDENTITY_PEM")
	if path == "" {
		t.Skip("set TEERMINATOR_CDS_IDENTITY_PEM to a captured CDS certificate to run")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return pemBytes
}

// The end-to-end property: a real CDS certificate verifies, and the claims it
// yields are the ones the cluster actually attested.
func TestAttestLiveCDSIdentity(t *testing.T) {
	id, err := AttestCDSIdentity(liveCDSIdentity(t), CDSPolicy{})
	if err != nil {
		t.Fatalf("AttestCDSIdentity: %v", err)
	}
	if id.LaunchDigest == "" {
		t.Fatal("no launch digest returned")
	}
	if !hasDigest(id.MeshCADigest) {
		t.Fatal("no mesh-CA digest in attested claims (claims v1?)")
	}
	if !hasDigest(id.AllowlistDigest) {
		t.Fatal("no live-allowlist digest in attested claims (claims v1/v2?)")
	}
	t.Logf("launch digest    %s", id.LaunchDigest)
	t.Logf("fingerprint      %s", id.FingerprintHex())
	t.Logf("meshCADigest     %s", hex.EncodeToString(id.MeshCADigest))
	t.Logf("allowlistDigest  %s", hex.EncodeToString(id.AllowlistDigest))
}

// A wrong measurement pin must reject a certificate that is otherwise genuine.
func TestLiveCDSIdentityRejectsWrongMeasurement(t *testing.T) {
	pemBytes := liveCDSIdentity(t)
	_, err := AttestCDSIdentity(pemBytes, CDSPolicy{
		Measurements: []string{"00" + hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 47))},
	})
	if err == nil {
		t.Fatal("a CDS certificate outside the measurement policy was accepted")
	}
	t.Logf("rejected as expected: %v", err)
}

// A wrong RTMR[3] pin must reject: same hardware, different deployment.
func TestLiveCDSIdentityRejectsWrongRTMR3(t *testing.T) {
	pemBytes := liveCDSIdentity(t)
	_, err := AttestCDSIdentity(pemBytes, CDSPolicy{
		ExpectedRTMR3: hex.EncodeToString(bytes.Repeat([]byte{0x11}, rtmr3Len)),
	})
	if err == nil {
		t.Fatal("a CDS certificate with a mismatched RTMR[3] was accepted")
	}
	t.Logf("rejected as expected: %v", err)
}

// Tampering with the published certificate must fail. This is what makes it
// safe to relay through an untrusted path.
func TestTamperedCDSIdentityRejected(t *testing.T) {
	pemBytes := liveCDSIdentity(t)
	tampered := bytes.Replace(pemBytes, []byte("A"), []byte("B"), 1)
	if bytes.Equal(tampered, pemBytes) {
		t.Skip("no byte to flip")
	}
	if _, err := AttestCDSIdentity(tampered, CDSPolicy{}); err == nil {
		t.Fatal("a tampered CDS certificate was accepted")
	}
}

// The mesh CA must be accepted only when it matches the attested digest, and
// rejected otherwise — this is the step that retires the out-of-band pin.
func TestVerifyMeshCABothDirections(t *testing.T) {
	id, err := AttestCDSIdentity(liveCDSIdentity(t), CDSPolicy{})
	if err != nil {
		t.Fatalf("AttestCDSIdentity: %v", err)
	}
	caPath := os.Getenv("TEERMINATOR_MESH_CA_PEM")
	if caPath == "" {
		t.Skip("set TEERMINATOR_MESH_CA_PEM to the CA served by the cluster")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read mesh CA: %v", err)
	}

	pool, err := id.VerifyMeshCA(caPEM)
	if err != nil {
		t.Fatalf("the CA CDS attested to issuing under was rejected: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool for a matching mesh CA")
	}

	// Negative: any other certificate must not pass as the mesh CA.
	if _, err := id.VerifyMeshCA(liveCDSIdentity(t)); err == nil {
		t.Fatal("a certificate that is not the attested mesh CA was accepted")
	}
}

// The served allowlist must hash to the attested digest, and any edit must be
// caught.
func TestVerifyAllowlistBothDirections(t *testing.T) {
	id, err := AttestCDSIdentity(liveCDSIdentity(t), CDSPolicy{})
	if err != nil {
		t.Fatalf("AttestCDSIdentity: %v", err)
	}
	alPath := os.Getenv("TEERMINATOR_ALLOWLIST_JSON")
	if alPath == "" {
		t.Skip("set TEERMINATOR_ALLOWLIST_JSON to the raw GET /allowlist bytes")
	}
	raw, err := os.ReadFile(alPath)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}

	if err := id.VerifyAllowlist(raw); err != nil {
		t.Fatalf("the allowlist CDS attested to serving was rejected: %v", err)
	}

	// A single appended byte — the classic trailing-newline mistake — must fail.
	if err := id.VerifyAllowlist(append(append([]byte(nil), raw...), '\n')); err == nil {
		t.Fatal("an allowlist with an extra byte was accepted")
	}
}

// Discovery plumbing: cds_identity is extracted, and its absence is an explicit
// error rather than a silent fallback to no verification.
func TestFetchCDSIdentityPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cds_identity": map[string]string{
				"certificate_pem":    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
				"certificate_sha256": "abcd",
			},
		})
	}))
	defer srv.Close()

	got, err := FetchCDSIdentityPEM(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchCDSIdentityPEM: %v", err)
	}
	if !bytes.Contains(got, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("unexpected PEM: %q", got)
	}
}

func TestFetchCDSIdentityAbsentIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "v1"})
	}))
	defer srv.Close()

	if _, err := FetchCDSIdentityPEM(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("a discovery document without cds_identity was accepted")
	}
}

// Claims that predate a field must not satisfy a request for it. Absence has to
// read as "not attested", never as a zero value that compares equal to nothing.
func TestOlderClaimsCannotSatisfyNewerProperties(t *testing.T) {
	v1 := &CDSIdentity{
		MeshCADigest:    append([]byte(nil), unsetDigest...),
		AllowlistDigest: append([]byte(nil), unsetDigest...),
	}
	if _, err := v1.VerifyMeshCA([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("v1 claims satisfied a mesh-CA derivation they never carried")
	}
	if err := v1.VerifyAllowlist([]byte("{}")); err == nil {
		t.Fatal("v1/v2 claims satisfied an allowlist check they never carried")
	}
}
