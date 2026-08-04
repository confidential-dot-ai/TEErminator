package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
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
	ok      bool
	verifAt time.Time
	err     error
	leaf    [32]byte // SHA-256 of the attested serving-leaf DER the session is pinned to
}

// NewSessionCache returns a cache whose verdicts are valid for ttl.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return &SessionCache{ttl: ttl, now: time.Now, state: make(map[string]verdict)}
}

// RecordSession stores an attestation verdict together with the SHA-256 of the
// attested serving-leaf DER the session is pinned to.
func (c *SessionCache) RecordSession(key string, ok bool, leaf [32]byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[key] = verdict{ok: ok, verifAt: c.now(), err: err, leaf: leaf}
}

// FreshSession returns the pinned leaf hash for a still-valid passing verdict.
// fresh is false when there is no unexpired verdict; ok reports whether that
// verdict passed.
func (c *SessionCache) FreshSession(key string) (leaf [32]byte, fresh, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, present := c.state[key]
	if !present || c.now().Sub(v.verifAt) > c.ttl {
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

// RemoteKey builds the verdict-cache key for a remote:
//
//	host + "|" + mode + "|" + hex(SHA-256(policy pins))
//
// where the pin digest covers, in order and each length-prefixed with a
// one-byte tag and uint32-BE length: the sorted lowercased measurement
// allowlist, the pinned workload name, the pinned allowlist file digest (when
// set), the pinned image-manifest file digest (when set), the expected-RTMR[3]
// pin, the SNP TCB floor (when set), and the sorted pinned-CA DER SHA-256
// fingerprints. Every policy input is part of the key, so a verdict cached
// under one policy or endpoint mode can never authorize traffic under another.
func RemoteKey(host string, r config.Remote, allowlistDigest, imageManifestDigest []byte, pinnedCAs []*x509.Certificate) string {
	h := sha256.New()
	field := func(tag byte, b []byte) {
		var n [5]byte
		n[0] = tag
		binary.BigEndian.PutUint32(n[1:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}

	meas := make([]string, len(r.Measurements))
	for i, m := range r.Measurements {
		meas[i] = strings.ToLower(m)
	}
	sort.Strings(meas)
	for _, m := range meas {
		field('m', []byte(m))
	}
	field('w', []byte(r.WorkloadName))
	if allowlistDigest != nil {
		field('a', allowlistDigest)
	}
	if imageManifestDigest != nil {
		field('i', imageManifestDigest)
	}
	field('r', []byte(strings.ToLower(r.ExpectedRTMR3)))
	if r.MinTCB != nil {
		field('t', fmt.Appendf(nil, "%d,%d,%d,%d",
			r.MinTCB.Bootloader, r.MinTCB.TEE, r.MinTCB.SNP, r.MinTCB.Microcode))
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
