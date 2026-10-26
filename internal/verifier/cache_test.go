package verifier

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func TestSessionCacheReusesVerdictWithinTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewSessionCache(time.Minute)
	c.now = func() time.Time { return now }

	if _, fresh, _ := c.FreshSession("host"); fresh {
		t.Fatal("expected no verdict before first RecordPass")
	}

	spki := [32]byte{4, 2}
	c.RecordPass("host", c.Now(), spki, now.Add(time.Hour))
	if got, fresh, ok := c.FreshSession("host"); !fresh || !ok || got != spki {
		t.Fatal("expected fresh+ok pinned verdict right after RecordPass")
	}

	// 30s later: still within the 60s TTL -> reused.
	now = now.Add(30 * time.Second)
	if _, fresh, ok := c.FreshSession("host"); !fresh || !ok {
		t.Fatal("expected verdict still fresh at 30s")
	}

	// 90s after RecordPass: expired -> must re-attest.
	now = now.Add(60 * time.Second)
	if _, fresh, _ := c.FreshSession("host"); fresh {
		t.Fatal("expected verdict to expire past TTL")
	}
}

func TestSessionCacheRemembersFailure(t *testing.T) {
	c := NewSessionCache(time.Minute)
	c.RecordFailure("bad", c.Now(), errors.New("boom"))
	_, fresh, ok := c.FreshSession("bad")
	if !fresh || ok {
		t.Fatalf("expected fresh failure verdict, got fresh=%v ok=%v", fresh, ok)
	}
	c.Invalidate("bad")
	if _, fresh, _ := c.FreshSession("bad"); fresh {
		t.Fatal("expected Invalidate to clear the verdict")
	}
}

// TestRecordKeepsLatestAttempt checks that the verdict of the attestation
// that began last wins, whichever order the verdicts are recorded in.
func TestRecordKeepsLatestAttempt(t *testing.T) {
	now := time.Unix(1000, 0)
	earlier, later := now.Add(-time.Second), now
	leaf := [32]byte{1}
	for _, tc := range []struct {
		name   string
		record func(c *SessionCache)
		wantOK bool
	}{
		{"failure that began before the pass", func(c *SessionCache) {
			c.RecordPass("host", later, leaf, now.Add(time.Hour))
			c.RecordFailure("host", earlier, errors.New("boom"))
		}, true},
		{"failure that began after the pass", func(c *SessionCache) {
			c.RecordPass("host", earlier, leaf, now.Add(time.Hour))
			c.RecordFailure("host", later, errors.New("boom"))
		}, false},
		{"pass that began before the failure", func(c *SessionCache) {
			c.RecordFailure("host", later, errors.New("boom"))
			c.RecordPass("host", earlier, leaf, now.Add(time.Hour))
		}, false},
		{"pass that began after the failure", func(c *SessionCache) {
			c.RecordFailure("host", earlier, errors.New("boom"))
			c.RecordPass("host", later, leaf, now.Add(time.Hour))
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewSessionCache(time.Minute)
			c.now = func() time.Time { return now }
			tc.record(c)
			if _, fresh, ok := c.FreshSession("host"); !fresh || ok != tc.wantOK {
				t.Errorf("FreshSession() = fresh %v, ok %v; want fresh, ok %v", fresh, ok, tc.wantOK)
			}
		})
	}
}

// TestExpiredServedLeafForcesReverify pins the second freshness bound: a
// verdict is scoped to one serving leaf, so it stops being reusable when that
// certificate expires even if the re-attest interval has not elapsed. The
// interval is caller-settable with no ceiling (StartOptions.ReattestInterval),
// while c8s caps a stamped leaf at 6h, so without this bound a generous
// interval would keep both the verdict and the handshake pin derived from it
// alive past the certificate's own lifetime.
func TestExpiredServedLeafForcesReverify(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewSessionCache(time.Hour)
	c.now = func() time.Time { return now }

	leaf := [32]byte{7}
	c.RecordPass("host", c.Now(), leaf, now.Add(10*time.Second))
	if _, fresh, ok := c.FreshSession("host"); !fresh || !ok {
		t.Fatal("verdict should be fresh inside both the TTL and the leaf validity")
	}

	// Past the leaf's NotAfter but well inside the one-hour TTL.
	now = now.Add(11 * time.Second)
	if _, fresh, _ := c.FreshSession("host"); fresh {
		t.Fatal("a verdict must not outlive the serving leaf it is scoped to")
	}

	// The TTL still binds independently: a long-lived leaf does not extend it.
	now = time.Unix(2000, 0)
	c.RecordPass("host", c.Now(), leaf, now.Add(24*time.Hour))
	now = now.Add(time.Hour + time.Second)
	if _, fresh, _ := c.FreshSession("host"); fresh {
		t.Fatal("a long-lived leaf must not extend the re-attest interval")
	}
}

// TestRemoteKey checks the cache key covers the endpoint mode and every policy
// pin, and is canonical over measurement order and case.
func TestRemoteKey(t *testing.T) {
	ca := mintCA(t, "key-test-ca")
	otherCA := mintCA(t, "other-key-test-ca")
	a1, b2 := launchDigestHex("a1"), launchDigestHex("b2")
	base := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{strings.ToUpper(b2), a1}}

	k := RemoteKey("lb.example:443", base, nil, nil)
	if !strings.HasPrefix(k, "lb.example:443|attest-lb|") {
		t.Fatalf("key = %q, want host|mode| prefix", k)
	}
	if k != RemoteKey("lb.example:443", base, nil, nil) {
		t.Fatal("key is not deterministic")
	}
	canon := base
	canon.Measurements = []string{" " + strings.ToUpper(a1) + " ", b2}
	if k != RemoteKey("lb.example:443", canon, nil, nil) {
		t.Fatal("key must be invariant under measurement order, case and whitespace")
	}

	variants := map[string]string{
		"different host": RemoteKey("other.example:443", base, nil, nil),
		"different mode": func() string {
			r := base
			r.Mode = config.AttestCDSCert
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"different measurements": func() string {
			r := base
			r.Measurements = []string{"a1"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"workload pin": func() string {
			r := base
			r.WorkloadName = "api"
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"expected rtmr3": func() string {
			r := base
			r.ExpectedRTMR3 = strings.Repeat("4d", RegisterSize)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"tcb floor": func() string {
			r := base
			r.MinTCB = &config.TCBFloor{Bootloader: 3, SNP: 8, Microcode: 209}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"other tcb floor": func() string {
			r := base
			r.MinTCB = &config.TCBFloor{Bootloader: 3, SNP: 8, Microcode: 210}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"tdx tcb status": func() string {
			r := base
			r.TDXTCBStatus = []string{"UpToDate"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"wider tdx tcb status": func() string {
			r := base
			r.TDXTCBStatus = []string{"UpToDate", "SWHardeningNeeded"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route digest pin": func() string {
			r := base
			r.RouteDigests = []string{strings.Repeat("ab", 32)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route operator key": func() string {
			r := base
			r.RouteOperatorKeys = []string{"-----BEGIN PUBLIC KEY-----"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"pinned policy": func() string {
			r := base
			r.PinnedPolicies = []string{"sha256:" + strings.Repeat("ab", 32)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"trust operator": func() string {
			r := base
			r.TrustOperator = true
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"trust operator key": func() string {
			r := base
			r.TrustOperator, r.TrustOperatorKeys = true, []string{"-----BEGIN PUBLIC KEY-----"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route floor": func() string {
			r := base
			r.RouteFloor = "3:" + strings.Repeat("ab", 32)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"rtmr pin": func() string {
			r := base
			r.RTMRs = []string{"1=" + strings.Repeat("4d", RegisterSize)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"init data": func() string {
			r := base
			r.InitDataDigest = strings.Repeat("ab", 32)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"sandbox id": func() string {
			r := base
			r.SandboxID = "sb"
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"pinned file":               RemoteKey("lb.example:443", base, map[string][]byte{"/a": {1, 2, 3}}, nil),
		"other pinned file":         RemoteKey("lb.example:443", base, map[string][]byte{"/b": {1, 2, 3}}, nil),
		"other pinned file content": RemoteKey("lb.example:443", base, map[string][]byte{"/a": {4, 5, 6}}, nil),
		"pinned CA":                 RemoteKey("lb.example:443", base, nil, []*x509.Certificate{ca.cert}),
		"other pinned CA":           RemoteKey("lb.example:443", base, nil, []*x509.Certificate{otherCA.cert}),
	}
	seen := map[string]string{k: "base"}
	for name, key := range variants {
		if prev, dup := seen[key]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[key] = name
	}

	reordered := base
	reordered.TDXTCBStatus = []string{"SWHardeningNeeded", "UpToDate"}
	if variants["wider tdx tcb status"] != RemoteKey("lb.example:443", reordered, nil, nil) {
		t.Fatal("key must be invariant under TDX TCB status order")
	}

	// Pinned-CA order must not matter.
	a := RemoteKey("h", base, nil, []*x509.Certificate{ca.cert, otherCA.cert})
	b := RemoteKey("h", base, nil, []*x509.Certificate{otherCA.cert, ca.cert})
	if a != b {
		t.Fatal("key must be invariant under pinned-CA order")
	}
}
