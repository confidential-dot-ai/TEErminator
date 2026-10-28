package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

const attestPath = "/.well-known/c8s/attest-lb"

// arrival is one request a fakeRouter answered, with its connection.
type arrival struct {
	conn string
	path string
}

// fakeRouter is an HTTP/1.1 front door that answers attest-lb with 200 and
// application requests with app, recording the connection of each request.
type fakeRouter struct {
	*httptest.Server
	mu   sync.Mutex
	seen []arrival
}

func newFakeRouter(t *testing.T, app http.HandlerFunc) *fakeRouter {
	t.Helper()
	r := &fakeRouter{}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, arrival{req.RemoteAddr, req.URL.Path})
		r.mu.Unlock()
		if req.URL.Path == attestPath {
			_, _ = io.WriteString(w, "attested")
			return
		}
		app(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *fakeRouter) arrivals() []arrival {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]arrival(nil), r.seen...)
}

func (r *fakeRouter) count(path string) int {
	n := 0
	for _, a := range r.arrivals() {
		if a.path == path {
			n++
		}
	}
	return n
}

// attestingDial stands in for EndpointAttester.Dial: it runs attest-lb on a
// new connection to r, then answers with judge's verdict for it.
func (r *fakeRouter) attestingDial(judge func() (*verifier.SessionVerdict, error)) func(context.Context) (*tls.Conn, *verifier.SessionVerdict, error) {
	return func(ctx context.Context) (*tls.Conn, *verifier.SessionVerdict, error) {
		dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}}
		raw, err := dialer.DialContext(ctx, "tcp", r.Listener.Addr().String())
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", verifier.ErrUnavailable, err)
		}
		conn := raw.(*tls.Conn)
		req, _ := http.NewRequest(http.MethodGet, r.URL+attestPath, nil)
		if err := req.Write(conn); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		v, err := judge()
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		return conn, v, nil
	}
}

func pass() (*verifier.SessionVerdict, error) {
	return &verifier.SessionVerdict{LeafNotAfter: time.Now().Add(time.Hour)}, nil
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestForwarder(t *testing.T, dial func(context.Context) (*tls.Conn, *verifier.SessionVerdict, error), reattest time.Duration, now func() time.Time) *attestedForwarder {
	t.Helper()
	f := &attestedForwarder{
		dial:     dial,
		remote:   "https://lb.test",
		failures: verifier.NewFailureMemo(reattest),
		key:      "lb.test",
		reattest: reattest,
		now:      now,
	}
	f.window = f.newWindow()
	t.Cleanup(func() {
		_ = f.Close()
	})
	return f
}

// response is the status and body a request through the forwarder got.
type response struct {
	status int
	body   string
}

// get sends GET url through f and returns the response it got.
func get(t *testing.T, f *attestedForwarder, url string) (response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.RoundTrip(req)
	if err != nil {
		return response{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{resp.StatusCode, string(body)}, nil
}

// failedWith reports whether err is an error whose message contains want.
func failedWith(err error, want string) bool {
	return err != nil && strings.Contains(err.Error(), want)
}

// attestedThenRequested reports whether a connection carried attest-lb and
// then one application request.
func attestedThenRequested(paths []string) bool {
	return len(paths) == 2 && paths[0] == attestPath && paths[1] == "/v1/chat"
}

func answerOK(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok")
}

func TestEachConnectionIsAttestedBeforeItCarriesARequest(t *testing.T) {
	const concurrent = 4
	var arrived sync.WaitGroup
	arrived.Add(concurrent)
	router := newFakeRouter(t, func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		arrived.Wait() // hold every request until all have their own connection
		answerOK(w, r)
	})
	f := newTestForwarder(t, router.attestingDial(pass), time.Minute, time.Now)

	var wg sync.WaitGroup
	for range concurrent {
		wg.Go(func() {
			if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	byConn := map[string][]string{}
	for _, a := range router.arrivals() {
		byConn[a.conn] = append(byConn[a.conn], a.path)
	}
	if len(byConn) != concurrent {
		t.Fatalf("requests rode %d connections, want %d", len(byConn), concurrent)
	}
	for conn, paths := range byConn {
		if !attestedThenRequested(paths) {
			t.Errorf("connection %s carried %v, want attest-lb then the request", conn, paths)
		}
	}
}

func TestAFailedAttestationSendsNoRequestAndIsRemembered(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	f := newTestForwarder(t, router.attestingDial(func() (*verifier.SessionVerdict, error) {
		return nil, errors.New("measurement not allowed")
	}), time.Minute, time.Now)

	for _, want := range []string{"measurement not allowed", "previously failed"} {
		if _, err := get(t, f, router.URL+"/v1/chat"); !failedWith(err, want) {
			t.Fatalf("RoundTrip() = %v, want an error containing %q", err, want)
		}
	}
	if got := router.count(attestPath); got != 1 {
		t.Errorf("attest-lb requests = %d, want 1: a remembered failure attests nothing", got)
	}
	if got := router.count("/v1/chat"); got != 0 {
		t.Errorf("%d request(s) reached the router after a failed attestation", got)
	}
}

func TestARouterThatCannotAttestNowIsNotRemembered(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	f := newTestForwarder(t, router.attestingDial(func() (*verifier.SessionVerdict, error) {
		return nil, fmt.Errorf("%w: attestation endpoint returned 503: sessions_busy", verifier.ErrUnavailable)
	}), time.Minute, time.Now)

	for range 2 {
		_, err := get(t, f, router.URL+"/v1/chat")
		if err == nil {
			t.Fatal("RoundTrip() passed while the router could not attest")
		}
		if failedWith(err, "previously failed") {
			t.Fatalf("RoundTrip() = %v, want the router's refusal itself", err)
		}
	}
	if got := router.count(attestPath); got != 2 {
		t.Errorf("attest-lb requests = %d, want 2: unavailability is not a verdict", got)
	}
}

func TestABindingRefusalRetiresTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		chunked bool // sent without a Content-Length
		retires bool
	}{
		{"route digest changed", http.StatusServiceUnavailable, "route_digest_changed\n", false, true},
		{"router digest changed", http.StatusServiceUnavailable, "router_digest_changed\n", false, true},
		{"binding expired", http.StatusServiceUnavailable, "binding_expired\n", false, true},
		{"a refusal of undeclared length", http.StatusServiceUnavailable, "router_digest_changed\n", true, true},
		{"another 503", http.StatusServiceUnavailable, "routes not applied\n", false, false},
		{"a code inside a longer body", http.StatusServiceUnavailable, "route_digest_changed" + strings.Repeat(" ", maxRefusalBytes), false, false},
		{"a code inside a longer body of undeclared length", http.StatusServiceUnavailable, "route_digest_changed" + strings.Repeat(" ", maxRefusalBytes), true, false},
		{"another status", http.StatusBadGateway, "route_digest_changed\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refused atomic.Bool
			router := newFakeRouter(t, func(w http.ResponseWriter, r *http.Request) {
				if refused.Swap(true) {
					answerOK(w, r)
					return
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, tc.body)
			})
			f := newTestForwarder(t, router.attestingDial(pass), time.Minute, time.Now)

			got, err := get(t, f, router.URL+"/v1/chat")
			if err != nil {
				t.Fatal(err)
			}
			if want := (response{tc.status, tc.body}); got != want {
				t.Fatalf("first request = %+v, want the router's %+v", got, want)
			}
			if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
				t.Fatal(err)
			}
			wantAttests := 1
			if tc.retires {
				wantAttests = 2
			}
			if got := router.count(attestPath); got != wantAttests {
				t.Errorf("attest-lb requests = %d, want %d", got, wantAttests)
			}
			if got := router.count("/v1/chat"); got != 2 {
				t.Errorf("application requests = %d, want 2: a refusal is not retried", got)
			}
		})
	}
}

func TestARequestInFlightFinishesOnARetiredWindow(t *testing.T) {
	streaming, finish := make(chan struct{}), make(chan struct{})
	router := newFakeRouter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/refuse" {
			http.Error(w, "router_digest_changed", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "first half ")
		w.(http.Flusher).Flush()
		close(streaming)
		<-finish
		_, _ = io.WriteString(w, "second half")
	})
	f := newTestForwarder(t, router.attestingDial(pass), time.Minute, time.Now)

	req, _ := http.NewRequest(http.MethodGet, router.URL+"/stream", nil)
	resp, err := f.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	<-streaming
	refusal, err := get(t, f, router.URL+"/refuse")
	if err != nil {
		t.Fatal(err)
	}
	if refusal.status != http.StatusServiceUnavailable {
		t.Fatalf("refusal status = %d, want 503", refusal.status)
	}
	close(finish)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("in-flight body: %v", err)
	}
	if string(body) != "first half second half" {
		t.Fatalf("in-flight body = %q, want it whole", body)
	}
}

func TestAWindowEndsAtTheReattestIntervalOrTheServingLeafExpiry(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	clock := &testClock{now: time.Unix(1000, 0)}
	leafNotAfter := clock.Now().Add(time.Hour)
	f := newTestForwarder(t, router.attestingDial(func() (*verifier.SessionVerdict, error) {
		return &verifier.SessionVerdict{LeafNotAfter: leafNotAfter}, nil
	}), time.Minute, clock.Now)

	steps := []struct {
		advance     time.Duration
		wantAttests int
	}{
		{0, 1},
		{59 * time.Second, 1},
		{2 * time.Second, 2}, // a minute after the window opened
	}
	for i, step := range steps {
		clock.advance(step.advance)
		if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
			t.Fatal(err)
		}
		if got := router.count(attestPath); got != step.wantAttests {
			t.Fatalf("step %d: attest-lb requests = %d, want %d", i, got, step.wantAttests)
		}
	}

	leafNotAfter = clock.Now().Add(10 * time.Second)
	f.retireCurrent()
	for _, advance := range []time.Duration{0, 11 * time.Second} {
		clock.advance(advance)
		if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
			t.Fatal(err)
		}
	}
	if got := router.count(attestPath); got != 4 {
		t.Fatalf("attest-lb requests = %d, want 4: a window ends when its serving leaf expires", got)
	}
}

func TestAZeroReattestIntervalAttestsEveryRequest(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	f := newTestForwarder(t, router.attestingDial(pass), 0, time.Now)
	for range 3 {
		if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
			t.Fatal(err)
		}
	}
	if got := router.count(attestPath); got != 3 {
		t.Fatalf("attest-lb requests = %d, want 3", got)
	}
}

func TestAFailedAttestationRetiresTheWindowsConnections(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	var fail atomic.Bool
	f := newTestForwarder(t, router.attestingDial(func() (*verifier.SessionVerdict, error) {
		if fail.Load() {
			return nil, errors.New("policy history not pinned")
		}
		return pass()
	}), time.Minute, time.Now)
	if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
		t.Fatal(err)
	}

	// A second connection of the window, as concurrent load would open,
	// fails verification.
	fail.Store(true)
	pooled := f.currentWindow()
	if _, err := f.dialAttested(context.Background(), pooled); err == nil {
		t.Fatal("dialAttested passed a failing verdict")
	}
	if f.currentWindow() == pooled {
		t.Fatal("the window whose attestation failed still takes new requests")
	}
	if _, err := get(t, f, router.URL+"/v1/chat"); !failedWith(err, "previously failed") {
		t.Fatalf("RoundTrip() = %v, want the remembered failure", err)
	}
	if got := router.count("/v1/chat"); got != 1 {
		t.Fatalf("application requests = %d, want 1: none after the failure", got)
	}
}

func TestARememberedFailureRefusesPooledConnections(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	f := newTestForwarder(t, router.attestingDial(pass), time.Minute, time.Now)
	if _, err := get(t, f, router.URL+"/v1/chat"); err != nil {
		t.Fatal(err)
	}
	// A dial of an earlier window fails while this one holds a connection.
	f.failures.RecordFailure(f.key, f.failures.Now(), errors.New("tcb out of date"))

	if _, err := get(t, f, router.URL+"/v1/chat"); !failedWith(err, "previously failed") {
		t.Fatalf("RoundTrip() = %v, want the remembered failure", err)
	}
	if got := router.count("/v1/chat"); got != 1 {
		t.Fatalf("application requests = %d, want 1: none while the failure is remembered", got)
	}
}

func TestAPassSupersededByALaterFailureForwardsNothing(t *testing.T) {
	router := newFakeRouter(t, answerOK)
	var f *attestedForwarder
	f = newTestForwarder(t, router.attestingDial(func() (*verifier.SessionVerdict, error) {
		f.failures.RecordFailure(f.key, f.failures.Now().Add(time.Second), errors.New("later attestation failed"))
		return pass()
	}), time.Minute, time.Now)

	if _, err := get(t, f, router.URL+"/v1/chat"); !failedWith(err, "previously failed") {
		t.Fatalf("RoundTrip() = %v, want the later failure", err)
	}
	if got := router.count("/v1/chat"); got != 0 {
		t.Fatalf("application requests = %d, want 0", got)
	}
}

func TestAnAbandonedDialIsNotRemembered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newTestForwarder(t, func(ctx context.Context) (*tls.Conn, *verifier.SessionVerdict, error) {
		return nil, nil, ctx.Err()
	}, time.Minute, time.Now)
	if _, err := f.dialAttested(ctx, f.currentWindow()); err == nil {
		t.Fatal("an abandoned dial returned a connection")
	}
	if err := f.failures.Failed(f.key); err != nil {
		t.Fatalf("an abandoned dial was remembered as a failure: %v", err)
	}
}

func TestAttestLBNeverForwardsOverPlainHTTP(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		answerOK(w, r)
	}))
	t.Cleanup(plain.Close)
	router := newFakeRouter(t, answerOK)
	f := newTestForwarder(t, router.attestingDial(pass), time.Minute, time.Now)
	if _, err := get(t, f, plain.URL+"/v1/chat"); err == nil {
		t.Fatal("a plain http request was forwarded")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the plain http server saw %d request(s)", got)
	}
}
