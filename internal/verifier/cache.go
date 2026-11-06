package verifier

import (
	"context"
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
	ttl      time.Duration
	now      func() time.Time
	mu       sync.Mutex
	state    map[string]verdict
	inflight map[string]*sessionRefresh
}

type sessionRefresh struct {
	done chan struct{}
	leaf [32]byte
	err  error
}

type verdict struct {
	ok bool
	// started is when the attestation began, verifAt when it was recorded.
	started time.Time
	verifAt time.Time
	err     error
	leaf    [32]byte // SHA-256 of the attested serving-leaf DER the session is pinned to
	// notAfter is the serving leaf expiry. A result cannot outlive its certificate.
	notAfter time.Time
}

// NewSessionCache returns a cache whose verdicts are valid for ttl.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return &SessionCache{ttl: ttl, now: time.Now, state: make(map[string]verdict), inflight: make(map[string]*sessionRefresh)}
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

// RecordFailure keeps a failed attempt for ordering. It cannot be reused.
func (c *SessionCache) RecordFailure(key string, started time.Time, err error) {
	_ = c.record(key, verdict{started: started, err: err}) // a newer verdict is kept either way
}

// record keeps whichever verdict comes from the attestation that began last,
// so a slow concurrent attestation never replaces newer evidence.
func (c *SessionCache) record(key string, v verdict) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recordLocked(key, v)
}

// recordLocked requires c.mu.
func (c *SessionCache) recordLocked(key string, v verdict) bool {
	if held, ok := c.state[key]; ok && held.started.After(v.started) {
		return false
	}
	v.verifAt = c.now()
	c.state[key] = v
	return true
}

// AttestedLeaf shares one check per key. Only successful checks can be reused.
// A caller can stop waiting without cancelling the check for other callers.
func (c *SessionCache) AttestedLeaf(ctx context.Context, key string, attest func(context.Context) (*SessionVerdict, error)) ([32]byte, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	c.mu.Lock()
	if leaf, fresh, ok := c.freshSession(key); fresh && ok {
		c.mu.Unlock()
		return leaf, nil
	}
	f := c.inflight[key]
	if f == nil {
		f = &sessionRefresh{done: make(chan struct{})}
		c.inflight[key] = f
		started := c.now()
		go func() {
			// Bound shared work even if all callers stop waiting.
			checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			v, err := attest(checkCtx)
			if err == nil && (v == nil || v.LeafSHA256 == ([32]byte{})) {
				err = fmt.Errorf("attestation returned no serving leaf")
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if err == nil {
				f.leaf = v.LeafSHA256
				if !c.recordLocked(key, verdict{ok: true, started: started, leaf: v.LeafSHA256, notAfter: v.LeafNotAfter}) {
					if held := c.state[key]; !held.ok {
						err = fmt.Errorf("a newer attestation failed: %w", held.err)
					}
				}
			} else {
				c.recordLocked(key, verdict{started: started, err: err})
			}
			f.err = err
			delete(c.inflight, key)
			close(f.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return [32]byte{}, ctx.Err()
	case <-f.done:
		return f.leaf, f.err
	}
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
	return c.freshSession(key)
}

// freshSession requires c.mu.
func (c *SessionCache) freshSession(key string) (leaf [32]byte, fresh, ok bool) {
	v, present := c.state[key]
	if !present || !v.ok {
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
		meas[i] = strings.ToLower(strings.TrimSpace(m))
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
