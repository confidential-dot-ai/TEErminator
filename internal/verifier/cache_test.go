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
		t.Fatal("expected no verdict before first RecordSession")
	}

	spki := [32]byte{4, 2}
	c.RecordSession("host", true, spki, nil)
	if got, fresh, ok := c.FreshSession("host"); !fresh || !ok || got != spki {
		t.Fatal("expected fresh+ok pinned verdict right after RecordSession")
	}

	// 30s later: still within the 60s TTL -> reused.
	now = now.Add(30 * time.Second)
	if _, fresh, ok := c.FreshSession("host"); !fresh || !ok {
		t.Fatal("expected verdict still fresh at 30s")
	}

	// 90s after RecordSession: expired -> must re-attest.
	now = now.Add(60 * time.Second)
	if _, fresh, _ := c.FreshSession("host"); fresh {
		t.Fatal("expected verdict to expire past TTL")
	}
}

func TestSessionCacheRemembersFailure(t *testing.T) {
	c := NewSessionCache(time.Minute)
	c.RecordSession("bad", false, [32]byte{}, errors.New("boom"))
	_, fresh, ok := c.FreshSession("bad")
	if !fresh || ok {
		t.Fatalf("expected fresh failure verdict, got fresh=%v ok=%v", fresh, ok)
	}
	c.Invalidate("bad")
	if _, fresh, _ := c.FreshSession("bad"); fresh {
		t.Fatal("expected Invalidate to clear the verdict")
	}
}

// TestRemoteKey checks the cache key covers the endpoint mode and every policy
// pin, and is canonical over measurement order and case.
func TestRemoteKey(t *testing.T) {
	ca := mintCA(t, "key-test-ca")
	otherCA := mintCA(t, "other-key-test-ca")
	base := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{"B2", "a1"}}

	k := RemoteKey("lb.example:443", base, nil, nil)
	if !strings.HasPrefix(k, "lb.example:443|attest-lb|") {
		t.Fatalf("key = %q, want host|mode| prefix", k)
	}
	if k != RemoteKey("lb.example:443", base, nil, nil) {
		t.Fatal("key is not deterministic")
	}
	canon := base
	canon.Measurements = []string{"A1", "b2"}
	if k != RemoteKey("lb.example:443", canon, nil, nil) {
		t.Fatal("key must be invariant under measurement order and case")
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
		"allowlist digest": RemoteKey("lb.example:443", base, []byte{1, 2, 3}, nil),
		"pinned CA":        RemoteKey("lb.example:443", base, nil, []*x509.Certificate{ca.cert}),
		"other pinned CA":  RemoteKey("lb.example:443", base, nil, []*x509.Certificate{otherCA.cert}),
	}
	seen := map[string]string{k: "base"}
	for name, key := range variants {
		if prev, dup := seen[key]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[key] = name
	}

	// Pinned-CA order must not matter.
	a := RemoteKey("h", base, nil, []*x509.Certificate{ca.cert, otherCA.cert})
	b := RemoteKey("h", base, nil, []*x509.Certificate{otherCA.cert, ca.cert})
	if a != b {
		t.Fatal("key must be invariant under pinned-CA order")
	}
}
