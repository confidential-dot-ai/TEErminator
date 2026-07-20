package verifier

import (
	"errors"
	"testing"
	"time"
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
