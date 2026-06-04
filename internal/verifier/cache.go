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
}

// NewSessionCache returns a cache whose verdicts are valid for ttl.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return &SessionCache{ttl: ttl, now: time.Now, state: make(map[string]verdict)}
}

// Fresh reports whether key has a still-valid verdict, and whether it passed.
// ok is only meaningful when fresh is true.
func (c *SessionCache) Fresh(key string) (fresh, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, present := c.state[key]
	if !present {
		return false, false
	}
	if c.now().Sub(v.verifAt) > c.ttl {
		return false, false
	}
	return true, v.ok
}

// Record stores the verdict for key as of now.
func (c *SessionCache) Record(key string, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[key] = verdict{ok: ok, verifAt: c.now(), err: err}
}

// Invalidate drops any cached verdict for key, forcing re-verification.
func (c *SessionCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.state, key)
}
