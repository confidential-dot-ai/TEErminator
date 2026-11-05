package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// meshRouter is an acme-mode router stand-in: one serving leaf (the httptest
// certificate) and a separate mesh leaf, served at meshLeafPath, that the test
// renews. It records the order of attestations, mesh-leaf fetches and
// application requests.
type meshRouter struct {
	t       *testing.T
	backend *httptest.Server

	mu         sync.Mutex
	meshPEM    []byte // what meshLeafPath serves
	meshStatus int    // status for meshLeafPath; 0 means 200
	meshDelay  time.Duration
	events     []string
	bodies     []string
}

func newMeshRouter(t *testing.T) *meshRouter {
	return newMeshRouterHTTP(t, false)
}

// newMeshRouterHTTP is newMeshRouter, serving HTTP/2 when h2 is set so that
// concurrent requests share one connection.
func newMeshRouterHTTP(t *testing.T, h2 bool) *meshRouter {
	t.Helper()
	r := &meshRouter{t: t}
	r.renew()
	r.backend = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == meshLeafPath {
			r.mu.Lock()
			r.events = append(r.events, "mesh")
			status, body, delay := r.meshStatus, r.meshPEM, r.meshDelay
			r.mu.Unlock()
			time.Sleep(delay)
			if status != 0 && status != http.StatusOK {
				http.Error(w, "no", status)
				return
			}
			_, _ = w.Write(body)
			return
		}
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.events = append(r.events, "app")
		r.bodies = append(r.bodies, string(body))
		r.mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	r.backend.EnableHTTP2 = h2
	r.backend.StartTLS()
	t.Cleanup(r.backend.Close)
	return r
}

// renew replaces the mesh leaf, as get-cert does when the allowlist changes.
// The served PEM is the leaf followed by a CA block: only the first block is
// the leaf.
func (r *meshRouter) renew() {
	leafPEM, _ := selfSignedCert(r.t, "mesh-leaf")
	caPEM, _ := selfSignedCert(r.t, "mesh-ca")
	r.mu.Lock()
	r.meshPEM = append(leafPEM, caPEM...)
	r.mu.Unlock()
}

// meshLeafHash is the SHA-256 of the mesh leaf DER the router holds now.
func (r *meshRouter) meshLeafHash() [32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	block, _ := pem.Decode(r.meshPEM)
	return sha256.Sum256(block.Bytes)
}

func (r *meshRouter) setMeshStatus(status int) {
	r.mu.Lock()
	r.meshStatus = status
	r.mu.Unlock()
}

func (r *meshRouter) setMeshBody(body []byte) {
	r.mu.Lock()
	r.meshPEM = body
	r.mu.Unlock()
}

func (r *meshRouter) record(event string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *meshRouter) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

// meshAttester stands in for the attest-lb verifier: it reports the serving
// leaf and the mesh leaf the router holds when it is called, as the bundle
// would, unless stale is set.
type meshAttester struct {
	r     *meshRouter
	stale *[32]byte // report this mesh leaf instead of the current one
	cds   bool      // cds front-door mode: the mesh leaf is the serving leaf
}

func (a *meshAttester) Attest(context.Context) (*verifier.SessionVerdict, error) {
	a.r.record("attest")
	cert := a.r.backend.Certificate()
	v := &verifier.SessionVerdict{
		LeafSHA256:       leafHashOf(cert),
		LeafNotAfter:     cert.NotAfter,
		MeshLeafNotAfter: time.Now().Add(time.Hour),
	}
	switch {
	case a.stale != nil:
		v.MeshLeafSHA256 = *a.stale
	default:
		v.MeshLeafSHA256 = a.r.meshLeafHash()
	}
	if a.cds {
		v.MeshLeafSHA256 = v.LeafSHA256
	}
	return v, nil
}

func newMeshTransport(t *testing.T, r *meshRouter, ea attester) *h3Transport {
	t.Helper()
	target, err := url.Parse(r.backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := newH3Transport(target, Options{
		Remote:           config.Remote{Mode: config.AttestEndpoint},
		ReattestInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tr.ea = ea
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func doMeshRequest(t *testing.T, tr *h3Transport, url, body string) error {
	t.Helper()
	var rd io.Reader
	method := http.MethodGet
	if body != "" {
		rd, method = strings.NewReader(body), http.MethodPost
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "ok" {
		t.Fatalf("body = %q, want ok", got)
	}
	return nil
}

// closeConnections makes the next request dial: the router closed the
// keep-alive connection, or it idled out.
func closeConnections(tr *h3Transport) {
	tr.pinnedMu.Lock()
	defer tr.pinnedMu.Unlock()
	for _, p := range tr.pinned {
		p.tr.CloseIdleConnections()
	}
}

// TestMeshLeafUnchangedReusesVerdict: with the mesh leaf unchanged, the cached
// verdict is reused, new connections check the mesh leaf once each, and a
// reused connection does not check it again.
func TestMeshLeafUnchangedReusesVerdict(t *testing.T) {
	r := newMeshRouter(t)
	tr := newMeshTransport(t, r, &meshAttester{r: r})

	for range 2 {
		if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
			t.Fatal(err)
		}
	}
	closeConnections(tr)
	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "prompt"); err != nil {
		t.Fatal(err)
	}

	want := []string{"attest", "mesh", "app", "app", "mesh", "app"}
	if got := r.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// TestMeshLeafChangedReattestsBeforeForwarding: a renewed mesh leaf (a new
// allowlist stamp under the same serving leaf) is found when the next
// connection is dialed. The request is not sent under the old verdict: the
// session re-attests, and the request, body intact, goes out under the new one.
func TestMeshLeafChangedReattestsBeforeForwarding(t *testing.T) {
	r := newMeshRouter(t)
	tr := newMeshTransport(t, r, &meshAttester{r: r})

	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "first"); err != nil {
		t.Fatal(err)
	}
	old, _, _ := tr.cache.FreshSession(tr.remoteKey)

	r.renew()
	closeConnections(tr)
	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "second"); err != nil {
		t.Fatalf("request after the mesh leaf renewed: %v", err)
	}

	want := []string{"attest", "mesh", "app", "mesh", "attest", "mesh", "app"}
	if got := r.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	r.mu.Lock()
	bodies := slices.Clone(r.bodies)
	r.mu.Unlock()
	if !slices.Equal(bodies, []string{"first", "second"}) {
		t.Fatalf("backend received bodies %q, want [first second]", bodies)
	}
	pin, fresh, ok := tr.cache.FreshSession(tr.remoteKey)
	if !fresh || !ok || pin.MeshLeaf != r.meshLeafHash() || pin.MeshLeaf == old.MeshLeaf {
		t.Fatalf("cached pin = %+v (fresh %v, ok %v), want the renewed mesh leaf", pin, fresh, ok)
	}
	tr.pinnedMu.Lock()
	_, kept := tr.pinned[old]
	tr.pinnedMu.Unlock()
	if kept {
		t.Error("the transport for the old mesh leaf was kept")
	}
}

// TestMeshLeafStillChangedRefuses: when the re-attested verdict also names a
// mesh leaf other than the one the router serves, the request is refused and
// never reaches the backend.
func TestMeshLeafStillChangedRefuses(t *testing.T) {
	r := newMeshRouter(t)
	stale := [32]byte{0xab}
	tr := newMeshTransport(t, r, &meshAttester{r: r, stale: &stale})

	err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "prompt")
	if !errors.Is(err, errMeshLeafChanged) {
		t.Fatalf("RoundTrip() = %v, want %v", err, errMeshLeafChanged)
	}
	want := []string{"attest", "mesh", "attest", "mesh"}
	if got := r.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if _, fresh, _ := tr.cache.FreshSession(tr.remoteKey); fresh {
		t.Error("verdict still cached after the mesh leaf check failed")
	}
}

// TestMeshLeafFetchFailureRefuses: when the mesh leaf cannot be read, the
// verdict cannot be shown to apply, so the request is refused (fail closed),
// never reaches the backend, and the verdict is dropped.
func TestMeshLeafFetchFailureRefuses(t *testing.T) {
	for _, tc := range []struct {
		name        string
		breakRouter func(r *meshRouter)
	}{
		{"not found", func(r *meshRouter) { r.setMeshStatus(http.StatusNotFound) }},
		{"server error", func(r *meshRouter) { r.setMeshStatus(http.StatusBadGateway) }},
		{"not a PEM certificate", func(r *meshRouter) { r.setMeshBody([]byte("<html>routed to the app</html>")) }},
		{"too large", func(r *meshRouter) { r.setMeshBody(make([]byte, maxMeshLeafPEM+1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newMeshRouter(t)
			ea := &meshAttester{r: r}
			tr := newMeshTransport(t, r, ea)
			// The verdict is recorded before the fetch fails.
			hash := r.meshLeafHash()
			ea.stale = &hash
			tc.breakRouter(r)

			err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "prompt")
			if !errors.Is(err, errMeshLeafUnverified) {
				t.Fatalf("RoundTrip() = %v, want %v", err, errMeshLeafUnverified)
			}
			for _, e := range r.log() {
				if e == "app" {
					t.Fatalf("request reached the backend: events %v", r.log())
				}
			}
			if _, fresh, _ := tr.cache.FreshSession(tr.remoteKey); fresh {
				t.Error("verdict still cached after the mesh leaf fetch failed")
			}
		})
	}
}

// TestMeshLeafCheckSkippedInCDSMode: when the mesh leaf is the serving leaf
// (cds front-door mode), the serving-leaf pin already covers it and nothing is
// fetched.
func TestMeshLeafCheckSkippedInCDSMode(t *testing.T) {
	r := newMeshRouter(t)
	r.setMeshStatus(http.StatusNotFound) // would fail closed if fetched
	tr := newMeshTransport(t, r, &meshAttester{r: r, cds: true})

	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
		t.Fatal(err)
	}
	if got, want := r.log(), []string{"attest", "app"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// fakeClock is the transport's clock for mesh-leaf check ages.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func useFakeClock(tr *h3Transport) *fakeClock {
	c := &fakeClock{now: time.Now()}
	tr.now = c.Now
	return c
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (r *meshRouter) count(event string) int {
	n := 0
	for _, e := range r.log() {
		if e == event {
			n++
		}
	}
	return n
}

// TestMeshLeafReusedConnectionWithinInterval: inside meshLeafRecheckInterval
// a request on a reused connection is forwarded without a fetch.
func TestMeshLeafReusedConnectionWithinInterval(t *testing.T) {
	r := newMeshRouter(t)
	tr := newMeshTransport(t, r, &meshAttester{r: r})
	clock := useFakeClock(tr)

	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
		t.Fatal(err)
	}
	clock.Advance(meshLeafRecheckInterval - time.Second)
	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
		t.Fatal(err)
	}
	if got, want := r.log(), []string{"attest", "mesh", "app", "app"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// TestMeshLeafReusedConnectionAfterInterval: once the last check is older
// than meshLeafRecheckInterval, a request on a reused connection checks the
// mesh leaf exactly once before it is forwarded, and the check covers the
// next interval.
func TestMeshLeafReusedConnectionAfterInterval(t *testing.T) {
	r := newMeshRouter(t)
	tr := newMeshTransport(t, r, &meshAttester{r: r})
	clock := useFakeClock(tr)

	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
		t.Fatal(err)
	}
	clock.Advance(meshLeafRecheckInterval + time.Second)
	for range 3 {
		if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"attest", "mesh", "app", "mesh", "app", "app", "app"}
	if got := r.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// TestMeshLeafReusedConnectionChanged: a mesh leaf renewed while the
// connection stays open is found by the next check after the interval. The
// request is not sent on the open connection: the session re-attests first,
// and the request, body intact, goes out under the new verdict.
func TestMeshLeafReusedConnectionChanged(t *testing.T) {
	r := newMeshRouter(t)
	tr := newMeshTransport(t, r, &meshAttester{r: r})
	clock := useFakeClock(tr)

	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "first"); err != nil {
		t.Fatal(err)
	}
	old, _, _ := tr.cache.FreshSession(tr.remoteKey)
	r.renew()
	clock.Advance(meshLeafRecheckInterval + time.Second)
	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", "second"); err != nil {
		t.Fatalf("request after the mesh leaf renewed: %v", err)
	}

	// The second "mesh" is the pre-forward check that finds the new leaf; the
	// third is the dial check of the new verdict's transport.
	want := []string{"attest", "mesh", "app", "mesh", "attest", "mesh", "app"}
	if got := r.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	r.mu.Lock()
	bodies := slices.Clone(r.bodies)
	r.mu.Unlock()
	if !slices.Equal(bodies, []string{"first", "second"}) {
		t.Fatalf("backend received bodies %q, want [first second]", bodies)
	}
	pin, fresh, ok := tr.cache.FreshSession(tr.remoteKey)
	if !fresh || !ok || pin.MeshLeaf == old.MeshLeaf {
		t.Fatalf("cached pin = %+v (fresh %v, ok %v), want the renewed mesh leaf", pin, fresh, ok)
	}
	tr.pinnedMu.Lock()
	_, kept := tr.pinned[old]
	tr.pinnedMu.Unlock()
	if kept {
		t.Error("the transport for the old mesh leaf was kept")
	}
}

// TestMeshLeafConcurrentRecheckFetchesOnce: concurrent requests on one pin
// that are all due a check share a single fetch.
func TestMeshLeafConcurrentRecheckFetchesOnce(t *testing.T) {
	r := newMeshRouterHTTP(t, true)
	tr := newMeshTransport(t, r, &meshAttester{r: r})
	clock := useFakeClock(tr)

	// One request opens the HTTP/2 connection the others share.
	if err := doMeshRequest(t, tr, r.backend.URL+"/v1/chat", ""); err != nil {
		t.Fatal(err)
	}
	if n := r.count("mesh"); n != 1 {
		t.Fatalf("mesh fetches after the first request = %d, want 1", n)
	}
	clock.Advance(meshLeafRecheckInterval + time.Second)
	r.mu.Lock()
	r.meshDelay = 100 * time.Millisecond // hold the check open while the others arrive
	r.mu.Unlock()

	const n = 8
	errs := make(chan error, n)
	for range n {
		go func() {
			req, err := http.NewRequest(http.MethodPost, r.backend.URL+"/v1/chat", strings.NewReader("prompt"))
			if err != nil {
				errs <- err
				return
			}
			resp, err := tr.RoundTrip(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := r.count("mesh"); got != 2 {
		t.Fatalf("mesh fetches = %d, want 2 (one dial check, one shared recheck)", got)
	}
	if got := r.count("app"); got != n+1 {
		t.Fatalf("app requests = %d, want %d", got, n+1)
	}
}
