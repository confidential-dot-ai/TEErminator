// Fingerprint-keyed caching for CDS attestation, with monotonic rollback
// detection.
//
// A CDS RA-TLS certificate is immutable once issued, so a verification verdict
// is a fact about a fingerprint, not about a point in time: as long as the
// freshly fetched certificate hashes to the fingerprint already verified and
// the clock is inside that certificate's validity window, the expensive quote
// verification can be skipped — the earlier verdict still stands. CDS re-issues
// the certificate whenever the live allowlist changes (and on restart), so a
// changed fingerprint is exactly the re-attestation signal.
//
// The cache is also where downgrade resistance lives. Every certificate's
// NotBefore is trustworthy after AttestCDSIdentity (REPORTDATA binds the SPKI;
// the self-signature extends that binding to the whole tbsCertificate), so
// "the new certificate must not be older than the last verified one" is an
// enforceable monotonic floor: a genuine-but-old (cert, allowlist) pair
// replayed by whoever controls the transport fails loudly instead of quietly
// rolling policy back.

package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// CachedAttestor wraps AttestCDSIdentity with fingerprint-keyed caching and
// monotonic rollback detection. The zero value is ready to use.
type CachedAttestor struct {
	// Attest runs the full verification. Nil means AttestCDSIdentity; tests
	// inject a counting stub to prove when the expensive path runs.
	Attest func(certPEM []byte, policy CDSPolicy) (*CDSIdentity, error)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// AllowRollback accepts a certificate older (by NotBefore) than the cached
	// one. Off by default: an older certificate is a rollback attempt unless
	// the operator is deliberately re-bootstrapping (e.g. against a restored
	// cluster) and says so.
	AllowRollback bool
}

func (a *CachedAttestor) attest(certPEM []byte, policy CDSPolicy) (*CDSIdentity, error) {
	if a.Attest != nil {
		return a.Attest(certPEM, policy)
	}
	return AttestCDSIdentity(certPEM, policy)
}

func (a *CachedAttestor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Verify attests certPEM against policy, consulting cached (nil = no cache).
//
// It returns the verified identity, the cache entry to persist (Target left
// empty for the caller to fill), and whether the verdict came from the cache.
// The entry is only ever returned on success, so persisting it cannot record
// an unverified certificate. On a cache hit the returned entry IS the cached
// one — VerifiedAt is not refreshed, because a hit reuses the old verdict
// rather than minting a new one.
func (a *CachedAttestor) Verify(certPEM []byte, policy CDSPolicy, cached *config.CDSIdentityCache) (*CDSIdentity, *config.CDSIdentityCache, bool, error) {
	fp, err := pemFingerprint(certPEM)
	if err != nil {
		return nil, nil, false, err
	}
	fpHex := hex.EncodeToString(fp[:])
	now := a.now()

	if cached != nil && cached.Fingerprint == fpHex {
		id, ok := identityFromCache(cached, fp, now)
		if ok {
			// The certificate is bit-identical to one already verified and
			// still inside its validity window — the quote verdict stands.
			// The POLICY may have changed since, though, so re-evaluate it
			// against the cached, signature-verified claims. Full
			// verification of the same bytes would surface the same claims,
			// so this is equivalent and catches a tightened pin.
			if err := checkMeasurement(cached.LaunchDigest, policy.Measurements); err != nil {
				return nil, nil, false, fmt.Errorf("cds-identity: %w", err)
			}
			satisfied, err := cachedRTMR3Satisfies(cached.RTMR3, policy.ExpectedRTMR3)
			if err != nil {
				return nil, nil, false, err
			}
			if satisfied {
				return id, cached, true, nil
			}
			// The cache predates the pin (no rtmr_3 recorded): fall through
			// to full verification, which enforces it or fails explaining why.
		}
		// Outside the validity window, or a corrupt entry: fall through and
		// re-verify. Same-fingerprint re-verification of an expired
		// certificate fails in AttestCDSIdentity, which is the point — an
		// expired verdict must not survive on either path.
	}

	id, err := a.attest(certPEM, policy)
	if err != nil {
		return nil, nil, false, err
	}

	// Monotonic fingerprint tracking: a re-issued certificate must not be
	// older than the one last verified. Both NotBefore values are trustworthy
	// (self-signature over the tbs, key REPORTDATA-bound), so an older
	// NotBefore on a different fingerprint means someone is replaying an old
	// (certificate, allowlist) pair — the downgrade this cache exists to
	// catch.
	//
	// Normal operation always moves forward: c8s pkg/ratls cert.go stamps
	// NotBefore with time.Now() at issuance, with no backdating skew, so a
	// CDS restart mints a certificate with a strictly newer NotBefore (fresh
	// key, fresh cert), as does every allowlist-change re-issue. Equal
	// NotBefore is accepted (>=): two issuances within clock granularity are
	// not a rollback. The only ways to trip this check are an actual replay
	// or CDS's clock moving backwards across a re-issue — and the latter is
	// exactly what --allow-rollback exists to recover from, deliberately and
	// loudly, rather than silently.
	if cached != nil && cached.Fingerprint != fpHex && id.NotBefore.Before(cached.NotBefore) {
		if !a.AllowRollback {
			return nil, nil, false, fmt.Errorf(
				"cds-identity: ROLLBACK REFUSED: fetched certificate %s (notBefore %s) is OLDER than the last verified certificate %s (notBefore %s) — "+
					"this looks like a replayed (certificate, allowlist) pair serving an outdated admission policy; "+
					"if this is a deliberate re-bootstrap (e.g. a restored cluster), re-run with --allow-rollback",
				fpHex, id.NotBefore.Format(time.RFC3339),
				cached.Fingerprint, cached.NotBefore.Format(time.RFC3339))
		}
	}

	entry := &config.CDSIdentityCache{
		Fingerprint:     fpHex,
		NotBefore:       id.NotBefore,
		NotAfter:        id.NotAfter,
		VerifiedAt:      now,
		LaunchDigest:    id.LaunchDigest,
		RTMR3:           id.RTMR3,
		MeshCADigest:    hex.EncodeToString(id.MeshCADigest),
		AllowlistDigest: hex.EncodeToString(id.AllowlistDigest),
	}
	return id, entry, false, nil
}

// DeriveMeshCAWithCache is DeriveMeshCA with the cache consulted around the
// attestation step. The mesh CA is fetched and digest-checked on every call —
// that check is cheap, and the trust store should converge on the CA the
// verified claims commit to even when the attestation verdict came from cache.
func (a *CachedAttestor) DeriveMeshCAWithCache(
	ctx context.Context,
	client *http.Client,
	discoveryURL, meshCAURL string,
	policy CDSPolicy,
	cached *config.CDSIdentityCache,
) ([]byte, *CDSIdentity, *config.CDSIdentityCache, bool, error) {
	certPEM, err := FetchCDSIdentityPEM(ctx, client, discoveryURL)
	if err != nil {
		return nil, nil, nil, false, err
	}
	id, entry, hit, err := a.Verify(certPEM, policy, cached)
	if err != nil {
		return nil, nil, nil, false, err
	}

	caPEM, err := fetchPEM(ctx, client, meshCAURL)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("cds-identity: fetch mesh CA: %w", err)
	}
	if _, err := id.VerifyMeshCA(caPEM); err != nil {
		return nil, nil, nil, false, err
	}
	return caPEM, id, entry, hit, nil
}

// pemFingerprint hashes the DER of the first CERTIFICATE block — the same
// bytes AttestCDSIdentity fingerprints, without the cost of parsing.
func pemFingerprint(certPEM []byte) ([32]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return [32]byte{}, fmt.Errorf("cds-identity: not a PEM CERTIFICATE")
	}
	return sha256.Sum256(block.Bytes), nil
}

// identityFromCache reconstructs the verified identity from a cache entry, or
// reports false when the entry cannot back a verdict: the clock is outside the
// certificate's validity window, or the entry is corrupt (bad hex, wrong digest
// width, no launch digest). False means "run full verification", never "trust
// less" — a damaged cache degrades to the expensive path, not to acceptance.
func identityFromCache(cached *config.CDSIdentityCache, fp [32]byte, now time.Time) (*CDSIdentity, bool) {
	if now.Before(cached.NotBefore) || now.After(cached.NotAfter) {
		return nil, false
	}
	if cached.LaunchDigest == "" {
		return nil, false
	}
	meshCA, err := hex.DecodeString(cached.MeshCADigest)
	if err != nil || len(meshCA) != claimsDigestSize {
		return nil, false
	}
	allowlist, err := hex.DecodeString(cached.AllowlistDigest)
	if err != nil || len(allowlist) != claimsDigestSize {
		return nil, false
	}
	return &CDSIdentity{
		Fingerprint:     fp,
		LaunchDigest:    cached.LaunchDigest,
		RTMR3:           cached.RTMR3,
		MeshCADigest:    meshCA,
		AllowlistDigest: allowlist,
		NotBefore:       cached.NotBefore,
		NotAfter:        cached.NotAfter,
	}, true
}

// cachedRTMR3Satisfies evaluates an RTMR[3] pin against the cached,
// signature-verified rtmr_3 claim. Returns (false, nil) when the cache carries
// no claim to compare — the caller must fall back to full verification, which
// either finds the claim on the quote or fails closed. A recorded claim that
// MISMATCHES the pin is an error, not a fallback: re-verifying the identical
// certificate would surface the identical claim, so the mismatch is final.
func cachedRTMR3Satisfies(cachedRTMR3, pin string) (bool, error) {
	if pin == "" {
		return true, nil
	}
	want, err := parseRTMR3(pin)
	if err != nil {
		return false, err
	}
	if cachedRTMR3 == "" {
		return false, nil
	}
	if cachedRTMR3 != hex.EncodeToString(want) {
		return false, fmt.Errorf("cds-identity: RTMR[3] mismatch: CDS reports %s, expected %s "+
			"(this is not the deployment the pin was taken from)", cachedRTMR3, hex.EncodeToString(want))
	}
	return true, nil
}
