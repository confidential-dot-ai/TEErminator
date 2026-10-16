package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/routes"
)

// routeManifest returns a valid manifest routing host; tag tells apart two
// manifests of the same revision.
func routeManifest(revision uint64, host, tag string) []byte {
	return fmt.Appendf(nil, `{"schema":"c8s.routes/v1","revision":%d,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{%q:{"routes":[{"path":"/%s","match":"prefix","backend":{"address":"api.ai.svc:8443","workload":"api"}}]}}}`, revision, host, tag)
}

// signRoutes returns the publication envelope for manifest, its write token
// signed with ES256 under key over signedBytes.
func signRoutes(t *testing.T, key *ecdsa.PrivateKey, manifest, signedBytes []byte) string {
	t.Helper()
	sum := sha256.Sum256(signedBytes)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"htm":"PUT","htu":"/routes","pbh":%q,"iat":1,"exp":61}`, base64.RawURLEncoding.EncodeToString(sum[:])))
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	env, err := json.Marshal(map[string]string{
		"manifest": base64.StdEncoding.EncodeToString(manifest),
		"token":    header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(env)
}

func operatorKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// publisher serves the given responses to successive publication
// fetches, repeating the last one. A response is an envelope, or a status
// code when it is a decimal number.
type publisher struct {
	mu        sync.Mutex
	responses []string
	fetches   int
}

func (p *publisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fetches
}

func (p *publisher) serve(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	resp := p.responses[min(p.fetches, len(p.responses)-1)]
	p.fetches++
	p.mu.Unlock()
	var status int
	if _, err := fmt.Sscanf(resp, "%d", &status); err == nil {
		http.Error(w, "refused", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(resp))
}

// newRoutedAttester builds an attester for baseURL whose connections go to
// the server addr names at each dial, so the remote URL host can be a DNS
// name a manifest routes.
func newRoutedAttester(t *testing.T, baseURL string, addr func() string, remote config.Remote) *EndpointAttester {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr())
		},
	}}
	ea, err := NewEndpointAttester(baseURL, client, remote, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ea
}

// routedServer starts a fixture LB that attests manifest's digest and
// serves pub at the publication path.
func routedServer(t *testing.T, f *lbFixture, manifest []byte, pub *publisher) *httptest.Server {
	t.Helper()
	d := sha256.Sum256(manifest)
	digest := hex.EncodeToString(d[:])
	return f.newServer(t, bundleSpec{transcriptRoute: d[:], routeDigest: &digest, routes: pub.serve})
}

func TestAttestLBRouteOperatorKeys(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const host = "app.example"
	m12, m13, m14 := routeManifest(12, host, "a"), routeManifest(13, host, "a"), routeManifest(14, host, "a")
	sign := func(m []byte) string { return signRoutes(t, key, m, m) }

	for _, tc := range []struct {
		name         string
		baseURL      string // default https://app.example
		attested     []byte
		responses    []string
		keys         []string // default: key
		digests      []string
		wantRevision uint64
		wantFetches  int
		wantErr      string
	}{
		{name: "operator-signed manifest", attested: m12, responses: []string{sign(m12)}, wantRevision: 12, wantFetches: 1},
		{name: "host compared without case or port", baseURL: "https://APP.example:8443", attested: m12, responses: []string{sign(m12)}, wantRevision: 12, wantFetches: 1},
		{name: "one of several keys", attested: m12, keys: []string{operatorKeyPEM(t, other), operatorKeyPEM(t, key)}, responses: []string{sign(m12)}, wantRevision: 12, wantFetches: 1},
		{name: "signed by another key", attested: m12, responses: []string{signRoutes(t, other, m12, m12)}, wantErr: "does not verify under route_operator_keys", wantFetches: 1},
		{name: "manifest changed after signing", attested: m13, responses: []string{signRoutes(t, key, m13, m12)}, wantErr: "pbh", wantFetches: 1},
		{name: "mismatch, then a higher revision", attested: m13, responses: []string{sign(m12), sign(m13)}, wantRevision: 13, wantFetches: 2},
		{name: "mismatch, then the same manifest", attested: m13, responses: []string{sign(m12), sign(m12)}, wantErr: "revisions 12 and 12", wantFetches: 4},
		{name: "mismatch, then a lower revision", attested: m12, responses: []string{sign(m13), sign(m12)}, wantRevision: 12, wantFetches: 2},
		{name: "mismatch, then a higher revision that also mismatches", attested: m14, responses: []string{sign(m12), sign(m13)}, wantErr: "route digest mismatch", wantFetches: 4},
		{name: "mismatch, then a failed re-fetch", attested: m13, responses: []string{sign(m12), "503"}, wantErr: "the re-fetch failed: GET /.well-known/c8s/routes returned 503: refused; after attesting again on new connections: attest-lb: GET /.well-known/c8s/routes returned 503", wantFetches: 3},
		{name: "publication off", attested: m12, responses: []string{"404"}, wantErr: "returned 404", wantFetches: 1},
		{name: "publication error", attested: m12, responses: []string{"500"}, wantErr: "returned 500", wantFetches: 1},
		{name: "malformed envelope", attested: m12, responses: []string{`{"manifest":"e30="}`}, wantErr: "route envelope", wantFetches: 1},
		{name: "host not routed", baseURL: "https://other.example", attested: m12, responses: []string{sign(m12)}, wantErr: `no routes for host "other.example"`, wantFetches: 1},
		{name: "both route checks", attested: m12, responses: []string{sign(m12)}, digests: []string{strings.Repeat("ab", 32)}, wantErr: "mutually exclusive"},
		{name: "malformed operator key", attested: m12, responses: []string{sign(m12)}, keys: []string{"not a key"}, wantErr: "configuration error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := &publisher{responses: tc.responses}
			ts := routedServer(t, f, tc.attested, pub)
			var addr atomic.Value
			addr.Store(ts.Listener.Addr().String())
			remote := measuredRemote()
			remote.RouteOperatorKeys = tc.keys
			if remote.RouteOperatorKeys == nil {
				remote.RouteOperatorKeys = []string{operatorKeyPEM(t, key)}
			}
			remote.RouteDigests = tc.digests
			baseURL := tc.baseURL
			if baseURL == "" {
				baseURL = "https://" + host
			}
			v, err := newRoutedAttester(t, baseURL, func() string { return addr.Load().(string) }, remote).Attest(context.Background())
			if got := pub.count(); got != tc.wantFetches {
				t.Errorf("publication fetches = %d, want %d", got, tc.wantFetches)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Attest() = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Attest() = %v, want success", err)
			}
			if v.RouteCheck != RouteOperatorSigned || v.RouteRevision != tc.wantRevision {
				t.Errorf("Attest() route check = %s revision %d, want %s revision %d", v.RouteCheck, v.RouteRevision, RouteOperatorSigned, tc.wantRevision)
			}
		})
	}
}

// TestAttestLBRouteFloor runs one attester through a sequence of routers:
// it keeps the last accepted revision and digest and refuses a rollback.
func TestAttestLBRouteFloor(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remote := measuredRemote()
	remote.RouteOperatorKeys = []string{operatorKeyPEM(t, key)}
	var addr atomic.Value
	ea := newRoutedAttester(t, "https://app.example", func() string { return addr.Load().(string) }, remote)

	for _, step := range []struct {
		name     string
		manifest []byte
		wantErr  string
	}{
		{"revision 13 accepted", routeManifest(13, "app.example", "a"), ""},
		{"the same manifest again", routeManifest(13, "app.example", "a"), ""},
		{"lower revision", routeManifest(12, "app.example", "a"), "a router replica may not have applied revision 13 yet"},
		{"same revision, other digest", routeManifest(13, "app.example", "b"), "equals the accepted one with a different digest"},
		{"higher revision accepted", routeManifest(14, "app.example", "a"), ""},
		{"the previously accepted revision", routeManifest(13, "app.example", "a"), "a router replica may not have applied revision 14 yet"},
		{"lagging publication replica, then the attested revision", routeManifest(14, "app.example", "a"), ""},
	} {
		pub := &publisher{responses: []string{signRoutes(t, key, step.manifest, step.manifest)}}
		if strings.HasPrefix(step.name, "lagging") {
			m13 := routeManifest(13, "app.example", "a")
			pub.responses = append([]string{signRoutes(t, key, m13, m13)}, pub.responses...)
		}
		addr.Store(routedServer(t, f, step.manifest, pub).Listener.Addr().String())
		_, err := ea.Attest(context.Background())
		if step.wantErr == "" && err != nil {
			t.Fatalf("%s: Attest() = %v, want success", step.name, err)
		}
		if step.wantErr != "" && (err == nil || !strings.Contains(err.Error(), step.wantErr)) {
			t.Fatalf("%s: Attest() = %v, want an error containing %q", step.name, err, step.wantErr)
		}
	}
}

func TestAttestLBRouteCheckReported(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{})
	for _, tc := range []struct {
		name string
		pins []string
		want string
	}{
		{"no route check", nil, RouteUnverified},
		{"digest pin", []string{hex.EncodeToString(fixtureRouteDigest[:])}, RoutePinned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := measuredRemote()
			remote.RouteDigests = tc.pins
			v, err := newLBAttester(t, ts, remote, nil).Attest(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if v.RouteCheck != tc.want || v.RouteRevision != 0 {
				t.Errorf("Attest() route check = %s revision %d, want %s revision 0", v.RouteCheck, v.RouteRevision, tc.want)
			}
		})
	}
}

// TestAttestLBRouteFloorReattests checks that a replica behind the floor,
// whose handshake and publication agree, gets one more attestation on new
// connections before the attester fails.
func TestAttestLBRouteFloorReattests(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remote := measuredRemote()
	remote.RouteOperatorKeys = []string{operatorKeyPEM(t, key)}
	server := func(m []byte) string {
		return routedServer(t, f, m, &publisher{responses: []string{signRoutes(t, key, m, m)}}).Listener.Addr().String()
	}
	m13, m14 := routeManifest(13, "app.example", "a"), routeManifest(14, "app.example", "a")
	current, lagging := server(m14), server(m13)
	// mixed attests m13 but publishes m14, as when the handshake reaches a
	// lagging replica and the publication a current one.
	mixed := routedServer(t, f, m13, &publisher{responses: []string{signRoutes(t, key, m14, m14)}}).Listener.Addr().String()

	for _, tc := range []struct {
		name    string
		dials   []string // one per connection, in order; the last repeats
		wantErr string
	}{
		// Each attempt dials twice: the handshake and the publication.
		{"current replica", []string{current}, ""},
		{"lagging replica, then a current one", []string{lagging, lagging, current}, ""},
		{"lagging replica twice", []string{lagging}, "a router replica may not have applied revision 14 yet"},
		// The third dial is the re-fetch, which also sees m14.
		{"handshake on a lagging replica, then a current one", []string{mixed, mixed, current}, ""},
		{"handshake on a lagging replica twice", []string{mixed}, "route digest mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			dials := 0
			addr := func() string {
				mu.Lock()
				defer mu.Unlock()
				dials++
				return tc.dials[min(dials, len(tc.dials))-1]
			}
			ea := newRoutedAttester(t, "https://app.example", addr, remote)
			if err := ea.routeFloor.Accept(mustVerify(t, key, m14)); err != nil {
				t.Fatal(err)
			}
			_, err := ea.Attest(context.Background())
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Attest() = %v, want success", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Attest() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// mustVerify returns m as a verified signed manifest.
func mustVerify(t *testing.T, key *ecdsa.PrivateKey, m []byte) *routes.Signed {
	t.Helper()
	env, err := routes.ParseEnvelope([]byte(signRoutes(t, key, m, m)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := routes.VerifySigned(env, []*ecdsa.PublicKey{&key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAttestLBFetchesPublicationAlongsideHandshake holds the attest-lb
// response until the publication request arrives, so it passes only when
// the publication fetch does not wait for the handshake.
func TestAttestLBFetchesPublicationAlongsideHandshake(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := routeManifest(12, "app.example", "a")
	pub := &publisher{responses: []string{signRoutes(t, key, m, m)}}
	requested := make(chan struct{})
	var once sync.Once
	var overlapped atomic.Bool
	d := sha256.Sum256(m)
	digest := hex.EncodeToString(d[:])
	ts := f.newServer(t, bundleSpec{
		transcriptRoute: d[:],
		routeDigest:     &digest,
		routes: func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(requested) })
			pub.serve(w, r)
		},
		observe: func(r *http.Request) {
			if r.URL.Path == wellKnownAttestLB {
				select {
				case <-requested:
					overlapped.Store(true)
				case <-time.After(5 * time.Second):
				}
			}
		},
	})
	remote := measuredRemote()
	remote.RouteOperatorKeys = []string{operatorKeyPEM(t, key)}
	addr := ts.Listener.Addr().String()
	ea := newRoutedAttester(t, "https://app.example", func() string { return addr }, remote)
	if _, err := ea.Attest(context.Background()); err != nil {
		t.Fatalf("Attest() = %v, want success", err)
	}
	if !overlapped.Load() {
		t.Error("the publication fetch waited for the attest-lb response")
	}
}
