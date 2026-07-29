package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// testCert generates a self-signed certificate with the given validity window
// and returns its PEM and hex SHA-256 fingerprint.
func testCert(t *testing.T, notBefore, notAfter time.Time) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test cds"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	fp := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(fp[:])
}

// countingAttestor counts full verifications and returns a fixed identity.
type countingAttestor struct {
	calls int
	id    *CDSIdentity
	err   error
}

func (c *countingAttestor) attest([]byte, CDSPolicy) (*CDSIdentity, error) {
	c.calls++
	return c.id, c.err
}

func cacheEntryFor(fingerprint string, notBefore, notAfter time.Time) *config.CDSIdentityCache {
	return &config.CDSIdentityCache{
		Target:          "https://front.door",
		Fingerprint:     fingerprint,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		VerifiedAt:      notBefore.Add(time.Minute),
		LaunchDigest:    "deadbeef",
		RTMR3:           validRTMR3,
		MeshCADigest:    strings.Repeat("44", 32),
		AllowlistDigest: strings.Repeat("55", 32),
	}
}

func TestCacheHitSkipsVerification(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	cached := cacheEntryFor(fp, now.Add(-time.Hour), now.Add(time.Hour))
	counter := &countingAttestor{}
	a := &CachedAttestor{Attest: counter.attest}

	id, entry, hit, err := a.Verify(certPEM, CDSPolicy{}, cached)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !hit {
		t.Fatal("expected a cache hit for an unchanged, in-window certificate")
	}
	if counter.calls != 0 {
		t.Fatalf("full verification ran %d times on a cache hit, want 0", counter.calls)
	}
	if id.FingerprintHex() != fp {
		t.Errorf("id fingerprint = %s, want %s", id.FingerprintHex(), fp)
	}
	if hex.EncodeToString(id.MeshCADigest) != cached.MeshCADigest {
		t.Errorf("mesh CA digest not reconstructed from cache")
	}
	if !entry.VerifiedAt.Equal(cached.VerifiedAt) {
		t.Errorf("a cache hit must not refresh VerifiedAt (reuses the old verdict)")
	}
}

func TestFingerprintChangeTriggersReverify(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	// Cached: a different certificate, older NotBefore (normal forward re-issue).
	cached := cacheEntryFor(strings.Repeat("ab", 32), now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		MeshCADigest: rep32(0x44),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	_, entry, hit, err := a.Verify(certPEM, CDSPolicy{}, cached)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d, want a full re-verification on a changed fingerprint", hit, counter.calls)
	}
	if entry.Fingerprint != fp {
		t.Errorf("new entry fingerprint = %s, want the fetched certificate's %s", entry.Fingerprint, fp)
	}
}

func TestRollbackRefused(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	// Cached: a NEWER certificate than the one now being served.
	cachedNotBefore := now.Add(-10 * time.Minute)
	cached := cacheEntryFor(strings.Repeat("ab", 32), cachedNotBefore, now.Add(24*time.Hour))
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		MeshCADigest: rep32(0x44),
		NotBefore:    now.Add(-time.Hour), // older than cached → rollback
		NotAfter:     now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	_, _, _, err := a.Verify(certPEM, CDSPolicy{}, cached)
	if err == nil {
		t.Fatal("a certificate older than the cached one was accepted")
	}
	for _, wants := range []string{"ROLLBACK REFUSED", fp, cached.Fingerprint, "--allow-rollback"} {
		if !strings.Contains(err.Error(), wants) {
			t.Errorf("rollback error %q does not name %q", err, wants)
		}
	}

	// The override accepts the same rollback, deliberately.
	a.AllowRollback = true
	if _, _, _, err := a.Verify(certPEM, CDSPolicy{}, cached); err != nil {
		t.Fatalf("--allow-rollback did not accept the rollback: %v", err)
	}
}

func TestEqualNotBeforeIsNotARollback(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	certPEM, _ := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	cached := cacheEntryFor(strings.Repeat("ab", 32), now.Add(-time.Hour), now.Add(time.Hour))
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		MeshCADigest: rep32(0x44),
		NotBefore:    cached.NotBefore, // equal, not older
		NotAfter:     now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}
	if _, _, _, err := a.Verify(certPEM, CDSPolicy{}, cached); err != nil {
		t.Fatalf("equal NotBefore refused as a rollback: %v", err)
	}
}

func TestExpiredCachedCertForcesReverify(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	cached := cacheEntryFor(fp, now.Add(-2*time.Hour), now.Add(-time.Hour)) // fingerprint matches, window over
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		MeshCADigest: rep32(0x44),
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	_, _, hit, err := a.Verify(certPEM, CDSPolicy{}, cached)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d: an expired cached verdict must force full re-verification "+
			"(which the real attestor then fails on expiry)", hit, counter.calls)
	}
}

// A cache hit must not bypass a policy that changed since the cache was
// written: the cached, signature-verified claims are re-evaluated.
func TestCacheHitStillEnforcesPolicy(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	cached := cacheEntryFor(fp, now.Add(-time.Hour), now.Add(time.Hour))
	counter := &countingAttestor{}
	a := &CachedAttestor{Attest: counter.attest}

	_, _, _, err := a.Verify(certPEM, CDSPolicy{Measurements: []string{"ffff"}}, cached)
	if err == nil || !strings.Contains(err.Error(), "not in the allowlist") {
		t.Fatalf("error = %v, want a measurement-policy rejection from cached claims", err)
	}

	otherRTMR3 := strings.Repeat("22", rtmr3Len)
	_, _, _, err = a.Verify(certPEM, CDSPolicy{ExpectedRTMR3: otherRTMR3}, cached)
	if err == nil || !strings.Contains(err.Error(), "RTMR[3] mismatch") {
		t.Fatalf("error = %v, want an RTMR[3] rejection from cached claims", err)
	}
	if counter.calls != 0 {
		t.Fatalf("policy mismatches on cached claims re-ran full verification %d times; "+
			"re-verifying identical bytes yields identical claims, so the mismatch is final", counter.calls)
	}

	// A matching pin is satisfied by the cached claim without re-verifying.
	if _, _, hit, err := a.Verify(certPEM, CDSPolicy{ExpectedRTMR3: validRTMR3}, cached); err != nil || !hit {
		t.Fatalf("hit=%v err=%v, want a cache hit for a pin the cached claims satisfy", hit, err)
	}
}

// A pin the cache carries no claim for must fall back to full verification —
// which either finds the claim on the quote or fails closed — never to a skip.
func TestCacheHitWithoutRTMR3FallsBackToFullVerify(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	cached := cacheEntryFor(fp, now.Add(-time.Hour), now.Add(time.Hour))
	cached.RTMR3 = "" // cache written before the pin existed
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		RTMR3:        validRTMR3,
		MeshCADigest: rep32(0x44),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	_, _, hit, err := a.Verify(certPEM, CDSPolicy{ExpectedRTMR3: validRTMR3}, cached)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d, want full verification when the cache carries no rtmr_3", hit, counter.calls)
	}
}

func TestCorruptCacheEntryDegradesToFullVerify(t *testing.T) {
	now := time.Now()
	certPEM, fp := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	cached := cacheEntryFor(fp, now.Add(-time.Hour), now.Add(time.Hour))
	cached.MeshCADigest = "not-hex"
	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest: "deadbeef",
		MeshCADigest: rep32(0x44),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	_, _, hit, err := a.Verify(certPEM, CDSPolicy{}, cached)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d, want a corrupt entry to degrade to full verification, never to trust", hit, counter.calls)
	}
}

// End to end over HTTP: first derive verifies fully and yields an entry; a
// second derive with that entry is a cache hit; the mesh CA is digest-checked
// on both.
func TestDeriveMeshCAWithCacheEndToEnd(t *testing.T) {
	now := time.Now()
	cdsPEM, _ := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	caPEM, _ := testCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	caBlock, _ := pem.Decode(caPEM)
	caDigest := sha256.Sum256(caBlock.Bytes)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/discovery", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cds_identity": map[string]string{"certificate_pem": string(cdsPEM)},
		})
	})
	mux.HandleFunc("/.well-known/mesh-ca.pem", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(caPEM)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	counter := &countingAttestor{id: &CDSIdentity{
		LaunchDigest:    "deadbeef",
		MeshCADigest:    caDigest[:],
		AllowlistDigest: rep32(0x55),
		NotBefore:       now.Add(-time.Hour),
		NotAfter:        now.Add(time.Hour),
	}}
	a := &CachedAttestor{Attest: counter.attest}

	ctx := context.Background()
	gotCA, _, entry, hit, err := a.DeriveMeshCAWithCache(ctx, srv.Client(),
		srv.URL+"/v1/discovery", srv.URL+"/.well-known/mesh-ca.pem", CDSPolicy{}, nil)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	if hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d, want a full verification with no cache", hit, counter.calls)
	}
	if !bytes.Equal(gotCA, caPEM) {
		t.Fatal("derived CA is not the served CA")
	}

	_, _, _, hit, err = a.DeriveMeshCAWithCache(ctx, srv.Client(),
		srv.URL+"/v1/discovery", srv.URL+"/.well-known/mesh-ca.pem", CDSPolicy{}, entry)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if !hit || counter.calls != 1 {
		t.Fatalf("hit=%v calls=%d, want a cache hit that skips re-verification", hit, counter.calls)
	}
}
