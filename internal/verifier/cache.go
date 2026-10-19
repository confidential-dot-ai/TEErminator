package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// SessionCache memoises attestation verdicts per remote so a long-lived TLS
// session is not re-attested on every request. Once a remote verifies, the
// verdict is reused until it ages past the configured interval — at which point
// the next request triggers a fresh verification. This implements the
// "longer-lived TLS sessions need not attest every request" refinement: a
// cached verdict is only reused while the connection still presents the exact
// attested leaf (the transport's handshake and response-time pins); a leaf
// change invalidates it and forces re-attestation.
type SessionCache struct {
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	state map[string]verdict
}

type verdict struct {
	ok bool
	// started is when the attestation began, verifAt when it was recorded.
	started time.Time
	verifAt time.Time
	err     error
	leaf    [32]byte // SHA-256 of the attested serving-leaf DER the session is pinned to
	// notAfter is that leaf's expiry, zero when the verdict pins no leaf (a
	// failure). A verdict is scoped to one certificate and cannot outlive it.
	notAfter time.Time
}

// NewSessionCache returns a cache whose verdicts are valid for ttl.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return &SessionCache{ttl: ttl, now: time.Now, state: make(map[string]verdict)}
}

// Now returns the time on the cache's clock, for the started argument of
// RecordPass and RecordFailure.
func (c *SessionCache) Now() time.Time { return c.now() }

// RecordPass stores a passing verdict for an attestation that began at
// started, with the SHA-256 of the attested serving-leaf DER the session is
// pinned to and that leaf's expiry.
// It reports whether it stored the verdict rather than keeping a newer one.
func (c *SessionCache) RecordPass(key string, started time.Time, leaf [32]byte, notAfter time.Time) bool {
	return c.record(key, verdict{ok: true, started: started, leaf: leaf, notAfter: notAfter})
}

// RecordFailure stores a failed attestation that began at started.
func (c *SessionCache) RecordFailure(key string, started time.Time, err error) {
	_ = c.record(key, verdict{started: started, err: err}) // a newer verdict is kept either way
}

// record keeps whichever verdict comes from the attestation that began last,
// so a slow concurrent attestation never replaces newer evidence.
func (c *SessionCache) record(key string, v verdict) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if held, ok := c.state[key]; ok && held.started.After(v.started) {
		return false
	}
	v.verifAt = c.now()
	c.state[key] = v
	return true
}

// FreshSession returns the pinned leaf hash for a still-valid passing verdict.
// fresh is false when there is no unexpired verdict; ok reports whether that
// verdict passed.
//
// Reuse is bounded by min(ttl, the pinned leaf's NotAfter). The ttl alone is
// not enough: it is the caller-settable ReattestInterval, with no ceiling, so a
// generous interval would otherwise keep a verdict — and the handshake pin
// derived from it — alive past the point where the certificate it is scoped to
// stopped being valid.
func (c *SessionCache) FreshSession(key string) (leaf [32]byte, fresh, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, present := c.state[key]
	if !present {
		return [32]byte{}, false, false
	}
	now := c.now()
	if now.Sub(v.verifAt) > c.ttl {
		return [32]byte{}, false, false
	}
	if !v.notAfter.IsZero() && !now.Before(v.notAfter) {
		return [32]byte{}, false, false
	}
	return v.leaf, true, v.ok
}

// Invalidate drops any cached verdict for key, forcing re-verification.
func (c *SessionCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.state, key)
}

// PinnedFileDigests returns the SHA-256 of every file a remote's pins name,
// keyed by path: the allowlist, the image manifest, the operator public key,
// and the pinned policy documents.
func PinnedFileDigests(r config.Remote) (map[string][]byte, error) {
	paths := []string{r.AllowlistPath, r.ImageManifestPath, r.OperatorPubkeyPath}
	for _, p := range r.PinnedPolicies {
		if !strings.HasPrefix(p, "sha256:") {
			paths = append(paths, p)
		}
	}
	files := make(map[string][]byte)
	for _, p := range paths {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read pinned file: %w", err)
		}
		sum := sha256.Sum256(raw)
		files[p] = sum[:]
	}
	return files, nil
}

// RemoteKey builds the verdict-cache key for a remote:
//
//	host + "|" + mode + "|" + hex(SHA-256(policy pins))
//
// where the pin digest covers every pin of r, each length-prefixed with a
// one-byte tag and uint32-BE length, list pins sorted and measurements
// lowercased; the digest of each pinned file (files, from PinnedFileDigests),
// sorted by path; and the sorted pinned-CA DER SHA-256 fingerprints. Every
// policy input is part of the key, so a verdict cached under one policy or
// endpoint mode can never authorize traffic under another.
func RemoteKey(host string, r config.Remote, files map[string][]byte, pinnedCAs []*x509.Certificate) string {
	h := sha256.New()
	field := func(tag byte, b []byte) {
		var n [5]byte
		n[0] = tag
		binary.BigEndian.PutUint32(n[1:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	sorted := func(tag byte, values []string) {
		values = slices.Clone(values)
		sort.Strings(values)
		for _, v := range values {
			field(tag, []byte(v))
		}
	}

	meas := make([]string, len(r.Measurements))
	for i, m := range r.Measurements {
		meas[i] = strings.ToLower(m)
	}
	sorted('m', meas)
	field('w', []byte(r.WorkloadName))
	field('r', []byte(strings.ToLower(r.ExpectedRTMR3)))
	if r.MinTCB != nil {
		field('t', fmt.Appendf(nil, "%d,%d,%d,%d",
			r.MinTCB.Bootloader, r.MinTCB.TEE, r.MinTCB.SNP, r.MinTCB.Microcode))
	}
	sorted('x', r.TDXTCBStatus)
	sorted('d', r.RouteDigests)
	sorted('k', r.RouteOperatorKeys)
	field('f', []byte(r.RouteFloor))
	sorted('R', r.RTMRs)
	field('n', []byte(strings.ToLower(r.InitDataDigest)))
	field('s', []byte(r.SandboxID))
	sorted('p', r.PinnedPolicies)
	field('T', []byte(strconv.FormatBool(r.TrustOperator)))
	sorted('o', r.TrustOperatorKeys)
	for _, path := range slices.Sorted(maps.Keys(files)) {
		field('a', []byte(path))
		field('h', files[path])
	}
	fps := make([]string, len(pinnedCAs))
	for i, ca := range pinnedCAs {
		sum := sha256.Sum256(ca.Raw)
		fps[i] = hex.EncodeToString(sum[:])
	}
	sort.Strings(fps)
	for _, fp := range fps {
		field('c', []byte(fp))
	}

	return host + "|" + string(r.Mode) + "|" + hex.EncodeToString(h.Sum(nil))
}
