package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// startTunnel is a test helper that creates a tunnel pointing at backend and
// registers cleanup to stop it when the test finishes.
func startTunnel(t *testing.T, ctx context.Context, backendURL, token string) *Tunnel {
	t.Helper()
	tunnel, err := Start(ctx, "127.0.0.1:0", backendURL, token)
	if err != nil {
		t.Fatalf("Start tunnel: %v", err)
	}
	t.Cleanup(func() { _ = tunnel.Stop() })
	return tunnel
}

func TestBasicGET(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello from backend")
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	resp, err := http.Get("http://" + tunnel.Addr())
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "hello from backend" {
		t.Errorf("body = %q, want %q", got, "hello from backend")
	}
	if got := resp.Header.Get("X-Custom"); got != "test-value" {
		t.Errorf("X-Custom header = %q, want %q", got, "test-value")
	}
}

func TestPOSTWithBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		fmt.Fprint(w, "echo: "+string(b))
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	resp, err := http.Post(
		"http://"+tunnel.Addr(),
		"text/plain",
		strings.NewReader("request-payload"),
	)
	if err != nil {
		t.Fatalf("POST through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "echo: request-payload" {
		t.Errorf("body = %q, want %q", got, "echo: request-payload")
	}
}

func TestPathJoining(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string // appended to backend URL
		reqPath    string // path sent to the tunnel
		wantPath   string // path the backend should see
	}{
		{
			name:       "prefix with trailing slash",
			remotePath: "/v1/",
			reqPath:    "/chat",
			wantPath:   "/v1/chat",
		},
		{
			name:       "prefix without trailing slash",
			remotePath: "/v1",
			reqPath:    "/chat",
			wantPath:   "/v1/chat",
		},
		{
			name:       "no prefix",
			remotePath: "",
			reqPath:    "/healthz",
			wantPath:   "/healthz",
		},
		{
			name:       "nested prefix",
			remotePath: "/api/v2/",
			reqPath:    "/users/42",
			wantPath:   "/api/v2/users/42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tunnel := startTunnel(t, ctx, backend.URL+tt.remotePath, "")

			resp, err := http.Get("http://" + tunnel.Addr() + tt.reqPath)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()

			if gotPath != tt.wantPath {
				t.Errorf("backend saw path %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}

func TestBearerTokenInjection(t *testing.T) {
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "my-secret-token")

	resp, err := http.Get("http://" + tunnel.Addr())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	want := "Bearer my-secret-token"
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestNoAuthHeaderWithoutToken(t *testing.T) {
	var hasAuth bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	resp, err := http.Get("http://" + tunnel.Addr())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if hasAuth {
		t.Error("Authorization header present when token is empty; want absent")
	}
}

func TestQueryParametersPreserved(t *testing.T) {
	var gotQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	resp, err := http.Get("http://" + tunnel.Addr() + "/search?q=hello&page=2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if gotQuery != "q=hello&page=2" {
		t.Errorf("query = %q, want %q", gotQuery, "q=hello&page=2")
	}
}

func TestRequestHeadersForwarded(t *testing.T) {
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	req, err := http.NewRequest("GET", "http://"+tunnel.Addr(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Request-ID", "abc-123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if gotHeader != "abc-123" {
		t.Errorf("X-Request-ID = %q, want %q", gotHeader, "abc-123")
	}
}

func TestContextCancellation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := Start(ctx, "127.0.0.1:0", backend.URL, "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify tunnel is operational.
	resp, err := http.Get("http://" + tunnel.Addr())
	if err != nil {
		t.Fatalf("GET before cancel: %v", err)
	}
	_ = resp.Body.Close()

	// Cancel the parent context; the tunnel should shut down.
	cancel()

	select {
	case <-tunnel.done:
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not shut down within timeout")
	}

	// New connections should be refused.
	client := &http.Client{Timeout: 2 * time.Second}
	_, err = client.Get("http://" + tunnel.Addr())
	if err == nil {
		t.Error("expected error after context cancellation, got nil")
	}
}

func TestStopGraceful(t *testing.T) {
	// Backend that deliberately delays its response.
	started := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "done")
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel, err := Start(ctx, "127.0.0.1:0", backend.URL, "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Fire a request that will be in-flight when Stop is called.
	var respBody string
	var reqErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get("http://" + tunnel.Addr())
		if err != nil {
			reqErr = err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		respBody = string(b)
	}()

	// Wait until the backend has started processing.
	<-started

	// Initiate graceful shutdown while the request is still in-flight.
	_ = tunnel.Stop()
	<-done

	if reqErr != nil {
		t.Fatalf("in-flight request failed: %v", reqErr)
	}
	if respBody != "done" {
		t.Errorf("body = %q, want %q", respBody, "done")
	}
}

func TestConcurrentRequests(t *testing.T) {
	var count atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel := startTunnel(t, ctx, backend.URL, "")

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get("http://" + tunnel.Addr())
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("status %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}

	if got := count.Load(); got != int64(n) {
		t.Errorf("backend received %d requests, want %d", got, n)
	}
}

func TestH3TransportFallback(t *testing.T) {
	// Use an HTTPS backend so that the h3Transport attempts HTTP/3 first.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "tls-ok")
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	transport, _ := newH3Transport(target, Options{})
	// Trust the test server's self-signed certificate for the fallback.
	transport.fallback.TLSClientConfig = backend.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", backend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "tls-ok" {
		t.Errorf("body = %q, want %q", got, "tls-ok")
	}

	// After a failed HTTP/3 attempt the host should be cached.
	transport.mu.RLock()
	marked := transport.noH3[target.Host]
	transport.mu.RUnlock()
	if !marked {
		t.Error("host should be marked as noH3 after HTTP/3 failure")
	}

	// A second request should skip H3 and go straight to fallback.
	req2, _ := http.NewRequest("GET", backend.URL, nil)
	resp2, err := transport.RoundTrip(req2)
	if err != nil {
		t.Fatalf("second RoundTrip: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	body2, _ := io.ReadAll(resp2.Body)
	if got := string(body2); got != "tls-ok" {
		t.Errorf("second body = %q, want %q", got, "tls-ok")
	}
}

func TestH3TransportPlainHTTPSkipsQUIC(t *testing.T) {
	// Plain HTTP should never attempt HTTP/3.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "plain-ok")
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	transport, _ := newH3Transport(target, Options{})
	defer func() { _ = transport.Close() }()

	req, err := http.NewRequest("GET", backend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "plain-ok" {
		t.Errorf("body = %q, want %q", got, "plain-ok")
	}

	// Host should NOT be marked since HTTP/3 was never attempted.
	transport.mu.RLock()
	marked := transport.noH3[target.Host]
	transport.mu.RUnlock()
	if marked {
		t.Error("host should not be marked as noH3 for plain HTTP")
	}
}

// newTrustingTransport builds an h3Transport for backend with the given options,
// trusting the test server's self-signed certificate on the fallback path.
func newTrustingTransport(t *testing.T, backend *httptest.Server, opts Options) *h3Transport {
	t.Helper()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := newH3Transport(target, opts)
	if err != nil {
		t.Fatalf("newH3Transport: %v", err)
	}
	tr.fallback.TLSClientConfig = backend.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestPerRemoteAttestationMethods verifies each tunnel enforces its own remote's
// attestation method independently: AttestNone forwards, attest fails closed
// when the backend cannot attest, and a recognised but not-yet-implemented
// method blocks the request before it ever reaches the backend.
func TestPerRemoteAttestationMethods(t *testing.T) {
	// A backend that serves no attestation endpoint.
	var hits atomic.Int64
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "backend-ok")
	}))
	defer backend.Close()

	cases := []struct {
		name        string
		mode        config.AttestMode
		wantError   bool
		wantForward bool // whether the backend may see the request
	}{
		{"none forwards", config.AttestNone, false, true},
		{"attest fails closed without valid attestation", config.AttestEndpoint, true, true},
		{"cds-cert (unimplemented) blocks before forwarding", config.AttestCDSCert, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			tr := newTrustingTransport(t, backend, Options{Remote: config.Remote{Mode: tc.mode}})
			req, _ := http.NewRequest("GET", backend.URL, nil)
			resp, err := tr.RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if tc.wantError && err == nil {
				t.Fatalf("mode %q: expected fail-closed error, got nil response forwarded", tc.mode)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("mode %q: expected forward, got error %v", tc.mode, err)
			}
			if !tc.wantForward && hits.Load() != 0 {
				t.Fatalf("mode %q: request reached the backend %d times; want it blocked at the proxy", tc.mode, hits.Load())
			}
		})
	}
}

// TestUnknownAttestationModeRejected ensures a config carrying an unrecognised
// (e.g. removed) attestation mode refuses to build a transport instead of
// silently forwarding unverified.
func TestUnknownAttestationModeRejected(t *testing.T) {
	target, _ := url.Parse("https://example.com")
	if _, err := newH3Transport(target, Options{Remote: config.Remote{Mode: "bogus-mode"}}); err == nil {
		t.Fatal("expected an error for an unrecognised attestation mode")
	}
}

func TestInvalidRemoteURL(t *testing.T) {
	ctx := context.Background()
	_, err := Start(ctx, "127.0.0.1:0", "://bad-url", "")
	if err == nil {
		t.Fatal("expected error for invalid remote URL, got nil")
	}
}

// selfSignedCert makes a self-signed cert (also usable as its own CA) whose only
// SAN is dnsName — deliberately no IP SAN.
func selfSignedCert(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// TestUpstreamServerNameAndCustomCA covers an upstream (like a c8s LB reached by
// public IP) whose cert is issued by a private CA and whose SAN is an internal
// DNS name with no IP. The Remote.ServerName override + ExtraCAs trust anchor must
// let it connect; without either, TLS validation must fail closed.
func TestUpstreamServerNameAndCustomCA(t *testing.T) {
	const sanName = "c8s-tls-lb.c8s-system.svc"
	certPEM, keyPEM := selfSignedCert(t, sanName)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-ok")
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	backend.StartTLS()
	defer backend.Close()

	target, err := url.Parse(backend.URL) // https://127.0.0.1:PORT — host has no matching SAN
	if err != nil {
		t.Fatal(err)
	}
	extraCAs := []config.Cert{{CommonName: sanName, PEM: string(certPEM)}}

	roundTrip := func(opts Options) error {
		tr, err := newH3Transport(target, opts)
		if err != nil {
			return err
		}
		defer func() { _ = tr.Close() }()
		req, _ := http.NewRequest("GET", backend.URL, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if got := string(body); got != "tls-ok" {
			return fmt.Errorf("body = %q, want tls-ok", got)
		}
		return nil
	}

	// CA trusted + ServerName overridden -> connects.
	if err := roundTrip(Options{ExtraCAs: extraCAs, Remote: config.Remote{ServerName: sanName}}); err != nil {
		t.Fatalf("CA + server-name should connect: %v", err)
	}
	// No ServerName override -> validated against the dial host (127.0.0.1), which
	// the cert does not cover -> fails closed.
	if err := roundTrip(Options{ExtraCAs: extraCAs}); err == nil {
		t.Error("expected TLS failure without --server-name (cert has no IP SAN)")
	}
	// ServerName overridden but CA not trusted -> fails closed.
	if err := roundTrip(Options{Remote: config.Remote{ServerName: sanName}}); err == nil {
		t.Error("expected TLS failure without trusting the custom CA")
	}
}

// leafHashOf returns the SHA-256 of a certificate's full DER, the exact-leaf
// value attestation verdicts pin sessions to.
func leafHashOf(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// TestPinnedLeafVerifier unit-tests the handshake-time pin. It is built for one
// decided leaf and has no permissive branch: it accepts that certificate and
// refuses everything else before application data flows, whatever the verdict
// cache happens to hold at the time.
func TestPinnedLeafVerifier(t *testing.T) {
	parse := func(pemBytes []byte) *x509.Certificate {
		block, _ := pem.Decode(pemBytes)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	pinnedPEM, pinnedKeyPEM := selfSignedCert(t, "pinned.example")
	otherPEM, _ := selfSignedCert(t, "other.example")
	pinned, other := parse(pinnedPEM), parse(otherPEM)

	verify := pinnedLeafVerifier(leafHashOf(pinned))

	state := func(cert *x509.Certificate) tls.ConnectionState {
		if cert == nil {
			return tls.ConnectionState{}
		}
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	if err := verify(state(pinned)); err != nil {
		t.Fatalf("pinned leaf: want handshake admitted, got %v", err)
	}
	if err := verify(state(other)); err == nil {
		t.Fatal("mismatched leaf: want handshake refused, got nil")
	}
	if err := verify(state(nil)); err == nil {
		t.Fatal("no peer certificate: want handshake refused, got nil")
	}

	// A different certificate over the SAME key must also be refused: the pin
	// is the exact leaf DER, not the SPKI.
	keyBlock, _ := pem.Decode(pinnedKeyPEM)
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pinnedKey := keyAny.(*ecdsa.PrivateKey)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "pinned.example"},
		DNSNames:     []string{"pinned.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	sameKeyDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pinnedKey.PublicKey, pinnedKey)
	if err != nil {
		t.Fatal(err)
	}
	sameKey, err := x509.ParseCertificate(sameKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(state(sameKey)); err == nil {
		t.Fatal("substituted certificate with the attested key: want handshake refused, got nil")
	}

	// The zero pin is not a wildcard. It cannot be reached from
	// roundTripEndpoint (a failed verdict returns before forwarding, and an
	// all-zero SHA-256 is not a certificate), but "no pin" must never read as
	// "any certificate".
	if err := pinnedLeafVerifier([32]byte{})(state(other)); err == nil {
		t.Fatal("zero pin: want handshake refused, got nil")
	}
}

// TestForwardingPinSurvivesCacheInvalidation is the regression for the
// fail-open race: the forwarding handshake used to re-read the shared verdict
// cache instead of using the pin its caller had already decided on, and
// returned nil — admitting ANY certificate — whenever that read came back
// stale. A concurrent request failing its response-time check
// (cache.Invalidate) or a TTL expiry at the boundary was enough to hit it,
// after which the bearer token and request body were written to an
// unattested peer.
//
// Reproduced deterministically here by invalidating the cache between the
// decision and the dial: the transport is built for backend A's leaf and then
// pointed at impostor B with the verdict already gone.
func TestForwardingPinSurvivesCacheInvalidation(t *testing.T) {
	attested := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "attested-ok")
	}))
	defer attested.Close()

	// httptest serves one shared certificate to every TLS server it starts, so
	// the impostor is given its own — otherwise it would present the very leaf
	// under test and prove nothing.
	impostorPEM, impostorKeyPEM := selfSignedCert(t, "impostor.example")
	impostorCert, err := tls.X509KeyPair(impostorPEM, impostorKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var impostorHits atomic.Int32
	impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		impostorHits.Add(1)
		fmt.Fprint(w, "impostor-ok")
	}))
	impostor.TLS = &tls.Config{Certificates: []tls.Certificate{impostorCert}}
	impostor.StartTLS()
	defer impostor.Close()

	target, err := url.Parse(impostor.URL) // the proxy is pointed at the impostor
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
	defer func() { _ = tr.Close() }()

	pin := leafHashOf(attested.Certificate())
	tr.cache.RecordSession(tr.remoteKey, true, pin, time.Now().Add(time.Hour), nil)
	forwarding := tr.transportFor(pin)

	// The race: the verdict vanishes after the caller decided on it and before
	// the handshake runs.
	tr.cache.Invalidate(tr.remoteKey)

	req, _ := http.NewRequest("GET", impostor.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := forwarding.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("request forwarded to an unattested peer after the verdict was invalidated")
	}
	if !strings.Contains(err.Error(), "does not match the attested leaf") {
		t.Fatalf("want the handshake pin error, got %v", err)
	}
	if got := impostorHits.Load(); got != 0 {
		t.Fatalf("%d request(s) reached the unattested backend; want 0", got)
	}
}

// TestHandshakePinBlocksBeforeSend covers the leak-one-request gap: with a
// fresh verdict pinning a leaf that is NOT the upstream's, the request must be
// refused during the TLS handshake — zero bytes reach the backend — while a
// verdict pinning the upstream's actual leaf forwards normally over the same
// transport construction.
func TestHandshakePinBlocksBeforeSend(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "attested-ok")
	}))
	defer backend.Close()

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Remote:           config.Remote{Mode: config.AttestEndpoint},
		ExtraCAs:         []config.Cert{{CommonName: "test-backend", PEM: string(leafPEM)}},
		ReattestInterval: time.Minute,
	}

	roundTrip := func(pin [32]byte) (string, error) {
		tr, err := newH3Transport(target, opts)
		if err != nil {
			t.Fatalf("newH3Transport: %v", err)
		}
		defer func() { _ = tr.Close() }()
		// Seed a fresh passing verdict directly so the round trip skips the
		// attester and exercises only the handshake-time pin.
		tr.cache.RecordSession(tr.remoteKey, true, pin, time.Now().Add(time.Hour), nil)
		req, _ := http.NewRequest("GET", backend.URL, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return string(body), nil
	}

	// Pin a leaf the upstream does not hold: the handshake must be refused and
	// the request must never reach the backend.
	if _, err := roundTrip([32]byte{0xde, 0xad}); err == nil {
		t.Fatal("mismatched pin: want a handshake error, got a forwarded response")
	} else if !strings.Contains(err.Error(), "does not match the attested leaf") {
		t.Fatalf("mismatched pin: want the handshake pin error, got %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("mismatched pin: %d request(s) reached the backend; want 0", got)
	}

	// Pin the upstream's actual leaf: forwards normally.
	body, err := roundTrip(leafHashOf(backend.Certificate()))
	if err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	if body != "attested-ok" {
		t.Fatalf("matching pin: body = %q, want attested-ok", body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("matching pin: backend hits = %d, want 1", got)
	}
}

func TestIsFenceRefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"fence", http.StatusServiceUnavailable, "the allowlist bound changed: open a new connection and attest again\n", true},
		{"other 503", http.StatusServiceUnavailable, "backend overloaded", false},
		{"fence text on 200", http.StatusOK, "the allowlist bound changed", false},
	} {
		resp := &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}
		if got := isFenceRefusal(resp); got != tc.want {
			t.Errorf("%s: isFenceRefusal = %v, want %v", tc.name, got, tc.want)
		}
		if body, _ := io.ReadAll(resp.Body); string(body) != tc.body {
			t.Errorf("%s: body after peek = %q, want %q", tc.name, body, tc.body)
		}
	}
}
