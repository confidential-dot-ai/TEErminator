package verifier

import (
	"sync"
	"time"
)

// SessionCache memoises attestation verdicts per remote so a long-lived TLS
// session is not re-attested on every request. Once a remote verifies, the
// verdict is reused until it ages past the configured interval — at which point
// the next request triggers a fresh verification. This implements the
// "longer-lived TLS sessions need not attest every request" refinement: the TLS
// channel carries the security guarantee once established, and re-attestation is
// a periodic freshness check rather than a per-request cost.
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
	spki    [32]byte // the attested LB leaf SPKI the session is pinned to
}

// NewSessionCache returns a cache whose verdicts are valid for ttl.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return &SessionCache{ttl: ttl, now: time.Now, state: make(map[string]verdict)}
}

// RecordSession stores a Flow B verdict together with the attested LB leaf SPKI
// the session is pinned to.
func (c *SessionCache) RecordSession(key string, ok bool, spki [32]byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[key] = verdict{ok: ok, verifAt: c.now(), err: err, spki: spki}
}

// FreshSession returns the pinned leaf SPKI for a still-valid passing Flow B
// verdict. fresh is false when there is no unexpired verdict; ok reports whether
// that verdict passed.
func (c *SessionCache) FreshSession(key string) (spki [32]byte, fresh, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, present := c.state[key]
	if !present || c.now().Sub(v.verifAt) > c.ttl {
		return [32]byte{}, false, false
	}
	return v.spki, true, v.ok
}

// Invalidate drops any cached verdict for key, forcing re-verification.
func (c *SessionCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.state, key)
}
