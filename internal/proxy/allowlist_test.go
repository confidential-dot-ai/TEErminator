package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// stubAttempts replaces the attest-then-fetch cycle with a scripted sequence of
// outcomes, so the retry decision can be exercised without live evidence. It
// returns a pointer to the call count.
func stubAttempts(t *testing.T, outcomes ...func() (*AllowlistFetch, error)) *int {
	t.Helper()
	calls := 0
	orig := allowlistAttempt
	allowlistAttempt = func(context.Context, config.Remote, []config.Cert) (*AllowlistFetch, error) {
		calls++
		if calls > len(outcomes) {
			t.Fatalf("attempt %d, want at most %d", calls, len(outcomes))
		}
		return outcomes[calls-1]()
	}
	t.Cleanup(func() { allowlistAttempt = orig })
	return &calls
}

func mismatch(served string) func() (*AllowlistFetch, error) {
	return func() (*AllowlistFetch, error) {
		return nil, &verifier.AllowlistDigestMismatch{
			StampedDigest:  make([]byte, 32),
			StampedVersion: "7",
			ServedVersion:  served,
		}
	}
}

func ok() (*AllowlistFetch, error) {
	return &AllowlistFetch{Document: &verifier.FetchedAllowlist{Workload: "api"}}, nil
}

func attestLBRemote(url string) config.Remote {
	return config.Remote{Local: "127.0.0.1:8080", Remote: url, Mode: config.AttestEndpoint}
}

// TestFetchAllowlistRetriesOnceOnMismatch: a digest mismatch is the ordinary
// consequence of an allowlist edited between the leaf's issuance and the fetch,
// so the whole flow re-runs once — and exactly once, since a second mismatch is
// a standing disagreement the operator has to see.
func TestFetchAllowlistRetriesOnceOnMismatch(t *testing.T) {
	ctx := context.Background()
	r := attestLBRemote("https://lb.example/")

	t.Run("re-attest resolves the race", func(t *testing.T) {
		calls := stubAttempts(t, mismatch("9"), ok)
		res, err := FetchAllowlist(ctx, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Reattested {
			t.Error("Reattested = false, want the caller told that the first fetch raced a change")
		}
		if *calls != 2 {
			t.Errorf("attempts = %d, want 2", *calls)
		}
	})

	t.Run("a second mismatch is reported, not retried again", func(t *testing.T) {
		calls := stubAttempts(t, mismatch("9"), mismatch("9"))
		_, err := FetchAllowlist(ctx, r, nil)
		var got *verifier.AllowlistDigestMismatch
		if !errors.As(err, &got) {
			t.Fatalf("want an AllowlistDigestMismatch, got %v", err)
		}
		if *calls != 2 {
			t.Errorf("attempts = %d, want 2", *calls)
		}
	})

	t.Run("a failed re-attest leaves the mismatch standing", func(t *testing.T) {
		stubAttempts(t, mismatch("9"), func() (*AllowlistFetch, error) {
			return nil, errors.New("connection refused")
		})
		_, err := FetchAllowlist(ctx, r, nil)
		var got *verifier.AllowlistDigestMismatch
		if !errors.As(err, &got) || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("want the mismatch with the retry failure named, got %v", err)
		}
	})

	t.Run("any other failure is not retried", func(t *testing.T) {
		calls := stubAttempts(t, func() (*AllowlistFetch, error) {
			return nil, errors.New("attest-lb: measurement not in the allowlist")
		})
		if _, err := FetchAllowlist(ctx, r, nil); err == nil {
			t.Fatal("want the attestation failure")
		}
		if *calls != 1 {
			t.Errorf("attempts = %d, want 1", *calls)
		}
	})
}

// TestFetchAllowlistRequiresAttestLB: without the attest-lb handshake there is
// no stamped digest to check a served document against, so the fetch refuses
// rather than downloading bytes nothing vouches for.
func TestFetchAllowlistRequiresAttestLB(t *testing.T) {
	for _, mode := range []config.AttestMode{config.AttestNone, config.AttestCDSCert} {
		r := attestLBRemote("https://lb.example/")
		r.Mode = mode
		_, err := FetchAllowlist(context.Background(), r, nil)
		if err == nil || !strings.Contains(err.Error(), "--mode attest-lb") {
			t.Errorf("mode %q: want a refusal naming attest-lb, got %v", mode, err)
		}
	}
}

// TestFetchAllowlistFailsClosedOnUnattestedBackend runs the real attempt (no
// seam) against a server that serves an allowlist but cannot attest: nothing is
// returned, because the document is only ever as good as the stamp naming it.
func TestFetchAllowlistFailsClosedOnUnattestedBackend(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`))
	}))
	defer ts.Close()

	r := attestLBRemote(ts.URL)
	r.Measurements = []string{"a1"}
	res, err := FetchAllowlist(context.Background(), r, caFor(t, ts))
	if err == nil {
		t.Fatalf("want an attestation failure, got %+v", res)
	}
}
