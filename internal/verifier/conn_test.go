package verifier

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// seenRequest is one request a fixture LB answered, with the connection it
// arrived on.
type seenRequest struct {
	remoteAddr string
	path       string
}

// recordingLB serves spec and records every request it answers.
func recordingLB(t *testing.T, f *lbFixture, spec bundleSpec) (*httptest.Server, func() []seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenRequest
	spec.observe = func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, seenRequest{r.RemoteAddr, r.URL.Path})
	}
	spec.routes = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "routed")
	}
	ts := f.newServer(t, spec)
	return ts, func() []seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenRequest(nil), seen...)
	}
}

// attestThenRoutedRequest reports whether seen is attest-lb followed by one
// routed request.
func attestThenRoutedRequest(seen []seenRequest) bool {
	return len(seen) == 2 && seen[0].path == wellKnownAttestLB && seen[1].path == wellKnownRoutes
}

// failedWith reports whether err is an error whose message contains want.
func failedWith(err error, want string) bool {
	return err != nil && strings.Contains(err.Error(), want)
}

func TestDialReturnsTheConnectionItAttested(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts, seen := recordingLB(t, f, bundleSpec{})
	ea := newLBAttester(t, ts, measuredRemote(), nil)

	conn, v, err := ea.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
	}()
	if want := sha256.Sum256(f.serving.cert.Raw); v.LeafSHA256 != want {
		t.Fatal("the verdict does not cover the connection's serving leaf")
	}
	req, err := http.NewRequest(http.MethodGet, ts.URL+wellKnownRoutes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("the attested connection carries no further request: %v", err)
	}
	_ = resp.Body.Close()

	got := seen()
	if !attestThenRoutedRequest(got) {
		t.Fatalf("requests = %+v, want attest-lb then the routed request", got)
	}
	if got[0].remoteAddr != got[1].remoteAddr {
		t.Fatalf("the request rode %s, attest-lb ran on %s", got[1].remoteAddr, got[0].remoteAddr)
	}
}

func TestDialRefusesAConnectionTheRouterCloses(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	bundle := f.handler(bundleSpec{})
	ts := f.serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		bundle(w, r)
	}))
	_, _, err := newLBAttester(t, ts, measuredRemote(), nil).Dial(context.Background())
	if !failedWith(err, "closes the connection") {
		t.Fatalf("Dial() = %v, want the closing connection refused", err)
	}
}

// renewingLB serves attest-lb, naming a renewed serving leaf on its first
// renewedAttempts attestations and the leaf it presents after that. It
// returns the server and its count of attest-lb requests.
func renewingLB(t *testing.T, renewedAttempts int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	f := newLBFixture(t, fixtureOpts{})
	renewed := mintLeaf(t, f.ca, "renewed-serving-leaf", nil)
	// The fixture names, in serving_leaf_sha256, the leaf it commits.
	namesRenewedLeaf := f.handler(bundleSpec{servingDER: renewed.cert.Raw})
	honest := f.handler(bundleSpec{})
	var attests atomic.Int32
	ts := f.serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attests.Add(1) <= renewedAttempts {
			namesRenewedLeaf(w, r)
			return
		}
		honest(w, r)
	}))
	return ts, &attests
}

func TestDialAttestsANewConnectionWhenTheLeafRenewedAfterTheHandshake(t *testing.T) {
	stubEvidence(t)
	ts, attests := renewingLB(t, 1)

	conn, _, err := newLBAttester(t, ts, measuredRemote(), nil).Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial() = %v, want a verdict from the second connection", err)
	}
	_ = conn.Close()
	if got := attests.Load(); got != 2 {
		t.Fatalf("attest-lb requests = %d, want 2", got)
	}
}

func TestDialFailsWhenTheLeafRenewedOnBothConnections(t *testing.T) {
	stubEvidence(t)
	ts, attests := renewingLB(t, 2)

	_, _, err := newLBAttester(t, ts, measuredRemote(), nil).Dial(context.Background())
	if !errors.Is(err, errServingLeafRenewed) {
		t.Fatalf("Dial() = %v, want errServingLeafRenewed", err)
	}
	if got := attests.Load(); got != 2 {
		t.Fatalf("attest-lb requests = %d, want 2: one retry", got)
	}
}

func TestDialMarksARouterThatCannotAttestNow(t *testing.T) {
	for _, tc := range []struct {
		status      int
		unavailable bool
	}{
		{http.StatusTooManyRequests, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusBadRequest, false},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			var attests atomic.Int32
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attests.Add(1)
				http.Error(w, "refused", tc.status)
			}))
			t.Cleanup(ts.Close)
			_, _, err := newLBAttester(t, ts, measuredRemote(), nil).Dial(context.Background())
			if err == nil {
				t.Fatal("Dial() passed against a refusing router")
			}
			if errors.Is(err, ErrUnavailable) != tc.unavailable {
				t.Fatalf("Dial() = %v, want ErrUnavailable %v", err, tc.unavailable)
			}
			if got := attests.Load(); got != 1 {
				t.Fatalf("attest-lb requests = %d, want 1", got)
			}
		})
	}

	t.Run("no listener", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.NotFoundHandler())
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		ts.Close()
		if _, _, err := ea.Dial(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Dial() = %v, want ErrUnavailable", err)
		}
	})
}

func TestNewEndpointAttesterRequiresHTTPS(t *testing.T) {
	if _, err := NewEndpointAttester(mustParseURL(t, "http://lb.example"), insecureTLS(nil), measuredRemote(), nil); err == nil {
		t.Fatal("an http remote was accepted for attest-lb")
	}
}
