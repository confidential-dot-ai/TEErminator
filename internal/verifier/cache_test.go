package verifier

import (
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func TestSessionCacheReusesVerdictWithinTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewSessionCache(time.Minute)
	c.now = func() time.Time { return now }

	if fresh, _ := c.Fresh("host"); fresh {
		t.Fatal("expected no verdict before first Record")
	}

	c.Record("host", true, nil)
	if fresh, ok := c.Fresh("host"); !fresh || !ok {
		t.Fatal("expected fresh+ok right after Record")
	}

	// 30s later: still within the 60s TTL -> reused.
	now = now.Add(30 * time.Second)
	if fresh, ok := c.Fresh("host"); !fresh || !ok {
		t.Fatal("expected verdict still fresh at 30s")
	}

	// 90s after Record: expired -> must re-verify.
	now = now.Add(60 * time.Second)
	if fresh, _ := c.Fresh("host"); fresh {
		t.Fatal("expected verdict to expire past TTL")
	}
}

func TestSessionCacheRemembersFailure(t *testing.T) {
	c := NewSessionCache(time.Minute)
	c.Record("bad", false, errors.New("boom"))
	fresh, ok := c.Fresh("bad")
	if !fresh || ok {
		t.Fatalf("expected fresh failure verdict, got fresh=%v ok=%v", fresh, ok)
	}
	c.Invalidate("bad")
	if fresh, _ := c.Fresh("bad"); fresh {
		t.Fatal("expected Invalidate to clear the verdict")
	}
}

func TestVerifierForMode(t *testing.T) {
	if v, err := For(""); err != nil || v != nil {
		t.Fatalf("AttestNone should yield nil verifier, got v=%v err=%v", v, err)
	}
	if v, err := For("tls-header"); err != nil || v == nil {
		t.Fatalf("tls-header should yield a verifier, got v=%v err=%v", v, err)
	}
	if _, err := For("bogus"); err == nil {
		t.Fatal("unknown mode should error")
	}
}

func TestFlowARejectsMissingHeader(t *testing.T) {
	v, _ := For("tls-header")
	_, err := v.Verify(Input{Remote: &config.Remote{}, ResponseHeader: nil})
	if err == nil {
		t.Fatal("expected error when response header is absent")
	}
}

func TestReportDataBindsNonce(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	rd := make([]byte, 64)
	copy(rd, nonce)
	if !reportDataBindsNonce(rd, nonce) {
		t.Fatal("expected raw-nonce prefix to bind")
	}
	rd2 := make([]byte, 64)
	if reportDataBindsNonce(rd2, nonce) {
		t.Fatal("zero report_data must not bind a nonzero nonce")
	}
}
