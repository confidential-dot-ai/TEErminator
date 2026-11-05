package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Options configures attestation enforcement for a tunnel.
type Options struct {
	// Remote is the full per-remote policy for this tunnel. Each tunnel enforces
	// its own remote's Mode/Measurements/DiscoveryURL/Pin independently of every
	// other tunnel, so TEErminator can front multiple attested backends at once
	// with a different attestation method per backend.
	Remote config.Remote
	// ReattestInterval is how long a successful verdict is reused before the next
	// request re-attests. Zero means re-verify on every request.
	ReattestInterval time.Duration
	// ExtraCAs are additional trust anchors (from `certs add`) appended to the
	// system roots when validating the upstream TLS certificate. This is what
	// lets TEErminator front a backend served by a private CA (e.g. a c8s mesh
	// CA) instead of a publicly-trusted one.
	ExtraCAs []config.Cert
}

// Tunnel is a running HTTP reverse proxy that forwards requests to a remote host.
type Tunnel struct {
	addr      string
	server    *http.Server
	transport *h3Transport
	cancel    context.CancelFunc
	done      chan struct{}
}

// Addr returns the network address the tunnel is listening on.
func (t *Tunnel) Addr() string { return t.addr }

// Start opens an HTTP listener on localAddr and reverse-proxies requests to
// remoteURL. Incoming request paths are joined with the path component of
// remoteURL so that, e.g., a request to /chat hitting a tunnel configured with
// https://api.example.com/v1/ is forwarded to https://api.example.com/v1/chat.
//
// If token is non-empty it is sent as a Bearer token in the Authorization
// header of every outgoing request.
//
// The provided context controls the tunnel lifetime: cancelling it initiates a
// graceful shutdown that lets in-flight requests finish for up to 5 seconds.
func Start(ctx context.Context, localAddr, remoteURL, token string) (*Tunnel, error) {
	return StartWithOptions(ctx, localAddr, remoteURL, Options{Remote: config.Remote{Token: token}})
}

// StartWithOptions is Start with explicit attestation enforcement options.
func StartWithOptions(ctx context.Context, localAddr, remoteURL string, opts Options) (*Tunnel, error) {
	target, err := url.Parse(remoteURL)
	if err != nil {
		return nil, fmt.Errorf("parsing remote URL: %w", err)
	}

	// localAddr may be a full URL (e.g. "http://localhost:8081") or a bare
	// host:port. Normalise to host:port so net.Listen accepts it.
	if parsed, err := url.Parse(localAddr); err == nil && parsed.Host != "" {
		localAddr = parsed.Host
	}

	transport, err := newH3Transport(target, opts)
	if err != nil {
		return nil, err
	}

	token := opts.Remote.Token
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host

			if token != "" {
				r.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		Transport: transport,
	}

	// watchCtx is derived from the parent; cancelling it (or the parent)
	// triggers the graceful-shutdown goroutine below.  We intentionally do
	// NOT pass it as BaseContext so that in-flight request contexts are not
	// cancelled before Shutdown has a chance to drain them.
	watchCtx, watchCancel := context.WithCancel(ctx)

	server := &http.Server{
		Handler: rp,
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		watchCancel()
		return nil, err
	}

	t := &Tunnel{
		addr:      ln.Addr().String(),
		server:    server,
		transport: transport,
		cancel:    watchCancel,
		done:      make(chan struct{}),
	}

	go func() {
		defer close(t.done)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("proxy: server %s: %v", localAddr, err)
		}
	}()

	go func() {
		<-watchCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("proxy: shutdown %s: %v", localAddr, err)
		}
	}()

	return t, nil
}

// Stop gracefully shuts down the tunnel, waiting for active requests to
// complete (up to 5 seconds) before forcefully closing connections.
func (t *Tunnel) Stop() error {
	t.cancel()
	<-t.done
	return t.transport.Close()
}

// h3Transport tries HTTP/3 (QUIC) first and falls back to standard HTTPS/HTTP.
// A per-host cache remembers hosts where HTTP/3 failed so that subsequent
// requests skip the QUIC attempt and go directly through the fallback.
// attester is the per-handshake attestation the transport gates on; tests
// replace it to control timing.
type attester interface {
	Attest(ctx context.Context) (*verifier.SessionVerdict, error)
}

type h3Transport struct {
	h3       *http3.Transport
	fallback *http.Transport

	// attestation enforcement (per-remote, independent of other tunnels)
	remote    config.Remote
	ea        attester // attest-lb mode: active per-handshake attester
	blocked   error    // set for recognised-but-unimplemented modes: fail closed without forwarding
	cache     *verifier.SessionCache
	remoteKey string
	// meshLeafURL is where the router serves its current mesh leaf
	// (meshLeafPath on the remote's origin), read on every new forwarding
	// connection whose pin names a separate mesh leaf (transportFor).
	meshLeafURL string
	// now is the clock for mesh-leaf check ages; tests replace it.
	now func() time.Time

	mu   sync.RWMutex
	noH3 map[string]bool

	// pinnedMu guards pinned, the per-pin forwarding transports built by
	// transportFor. Keying the connection pool by pin is what makes the
	// handshake check answerable from the request alone: a pooled connection
	// can only ever be reused by a request that decided on the same leaves.
	pinnedMu sync.Mutex
	pinned   map[verifier.SessionPin]*pinnedTransport
}

// pinnedTransport is the forwarding transport for one pin, with the state of
// its mesh-leaf checks.
type pinnedTransport struct {
	tr *http.Transport
	// check fetches the router's current mesh leaf and compares it with the
	// pin (checkMeshLeaf). It is nil when the pin needs no mesh-leaf check.
	check func(ctx context.Context) error

	// flight is held for the whole of a pre-forward check, so concurrent
	// requests on this pin wait for one fetch instead of each running their own.
	flight sync.Mutex

	mu sync.Mutex
	// checkedAt is when the newest passing observation of the mesh leaf began:
	// a pre-forward check, a dial check, or the attestation the pin came from.
	checkedAt time.Time
	// failed is the first failed check. A pin whose check failed stays failed:
	// its verdict is dropped and the session re-attests under a new transport.
	failed error
}

// meshLeafPath is where a c8s router serves its current mesh leaf PEM on the
// public serving port, with no client certificate (the c8s chart value
// router.discovery.cdsCertPath). nginx reads the file get-cert replaces on
// every renewal, which is the file the attest-lb bundle embeds.
const meshLeafPath = "/.well-known/cds-cert.pem"

const (
	// meshLeafCheckTimeout bounds the mesh-leaf fetch that runs before a new
	// forwarding connection is dialed.
	meshLeafCheckTimeout = 10 * time.Second
	// maxMeshLeafPEM bounds the response read: a leaf, its chain and a CA.
	maxMeshLeafPEM = 64 << 10
	// meshLeafRecheckInterval is how long a passing mesh-leaf check covers a
	// request on a reused connection; after it, the next such request checks
	// again before it is forwarded (one fetch per pin, whatever the request
	// rate). New connections are checked on every dial regardless.
	//
	// 5s matches how often c8s nodes poll CDS for the allowlist, so a check
	// adds at most about one poll period to the time a renewed mesh leaf takes
	// to reach the proxy; the router itself renews within about 1.5 minutes of
	// an upload. Shorter would add fetches without making the stamp current
	// much sooner; longer would leave reused connections on an old stamp for
	// longer than the cluster takes to notice the change.
	meshLeafRecheckInterval = 5 * time.Second
)

var (
	// errMeshLeafChanged: the router serves a mesh leaf other than the
	// attested one, so the matched-workload stamp the verdict read may be
	// out of date (an allowlist change renews the mesh leaf, not the serving
	// leaf). The verdict is dropped and the session re-attests.
	errMeshLeafChanged = errors.New("router mesh leaf changed since attestation (re-attest required)")
	// errMeshLeafUnverified: the current mesh leaf could not be read, so the
	// verdict cannot be shown to still apply. Fail closed.
	errMeshLeafUnverified = errors.New("cannot confirm the router's mesh leaf")
)

// upstreamTLSConfig builds the TLS client config used to validate an upstream:
// the certificate is checked against the remote's ServerName override when set
// (otherwise the URL host — the override covers backends reached by an IP or
// any name whose certificate only carries a different SAN), and operator-added
// CAs (`certs add`) are appended to the system trust store so a
// privately-issued upstream cert (e.g. c8s mesh CA) verifies. With no extra
// CAs, RootCAs stays nil and the system roots are used unchanged.
func upstreamTLSConfig(target *url.URL, remote config.Remote, extraCAs []config.Cert) (*tls.Config, error) {
	serverName := target.Hostname()
	if remote.ServerName != "" {
		serverName = remote.ServerName
	}
	tlsCfg := &tls.Config{
		ServerName: serverName,
	}
	if len(extraCAs) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, c := range extraCAs {
			if !pool.AppendCertsFromPEM([]byte(c.PEM)) {
				return nil, fmt.Errorf("trust store: failed to parse stored CA %q", c.CommonName)
			}
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// parseExtraCAs parses every `certs add` PEM into a certificate. In attest-lb
// mode these are the operator's optional mesh-CA pins: a committed CA that
// byte-equals one of them upgrades the verdict to specific-cluster.
func parseExtraCAs(extraCAs []config.Cert) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, c := range extraCAs {
		block, _ := pem.Decode([]byte(c.PEM))
		if block == nil {
			return nil, fmt.Errorf("trust store: no PEM block in stored CA %q", c.CommonName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust store: failed to parse stored CA %q: %w", c.CommonName, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func newH3Transport(target *url.URL, opts Options) (*h3Transport, error) {
	tlsCfg, err := upstreamTLSConfig(target, opts.Remote, opts.ExtraCAs)
	if err != nil {
		return nil, err
	}

	var (
		ea          attester
		blocked     error
		cache       *verifier.SessionCache
		remoteKey   = target.Host
		meshLeafURL string
	)
	// Attested traffic forwards over the fallback transport, so that is where
	// the handshake-time leaf pin lives: refusing a mismatched leaf during the
	// handshake means no request bytes (body, bearer token) are ever written
	// to an endpoint other than the attested one.
	fallbackTLS := tlsCfg.Clone()

	switch opts.Remote.Mode {
	case config.AttestNone:
		// No attestation: plain forwarding over WebPKI/system-pool trust.
	case config.AttestEndpoint:
		pinnedCAs, err := parseExtraCAs(opts.ExtraCAs)
		if err != nil {
			return nil, err
		}
		// The cache key covers the endpoint mode and every policy pin, so a
		// verdict cached under one policy can never authorize another.
		files, err := verifier.PinnedFileDigests(opts.Remote)
		if err != nil {
			return nil, fmt.Errorf("attest-lb: %w", err)
		}
		remoteKey = verifier.RemoteKey(target.Host, opts.Remote, files, pinnedCAs)
		cache = verifier.NewSessionCache(opts.ReattestInterval)

		// The first handshake captures the serving leaf before its attested mode
		// is known. No application bytes flow before verification. The verifier
		// then requires a mesh-CA chain in cds mode, or WebPKI name and chain
		// validation in acme mode, and binds the exact serving-leaf DER into
		// fresh hardware evidence (roundTripEndpoint).
		// Forwarding handshakes additionally carry the decided leaf pin
		// (transportFor). WebPKI/system-pool verification stays in force for
		// every mode not gated by an attest-lb verdict.
		attestTLS := &tls.Config{
			ServerName:         tlsCfg.ServerName,
			RootCAs:            tlsCfg.RootCAs,
			InsecureSkipVerify: true, // replaced by the attest-lb hardware binding above
		}
		fallbackTLS = attestTLS.Clone()

		// The attester fetches the bundle itself, over a transport built with
		// the same trust construction the proxy forwards over, so the leaf it
		// observes (and the evidence binds) is the one traffic rides.
		attestClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: attestTLS.Clone()},
			Timeout:   30 * time.Second,
		}
		baseURL := target.Scheme + "://" + target.Host
		meshLeafURL = baseURL + meshLeafPath
		ea, err = verifier.NewEndpointAttester(baseURL, attestClient, opts.Remote, pinnedCAs, tlsCfg.RootCAs)
		if err != nil {
			return nil, err
		}
	case config.AttestCDSCert:
		// Recognised but not yet implemented: block every request rather than
		// forwarding it to an unverified backend.
		blocked = fmt.Errorf("%w: %s (use the c8s-verify-js browser client for this flow today)",
			verifier.ErrNotImplemented, opts.Remote.Mode)
	default:
		return nil, fmt.Errorf("unknown attestation mode %q", opts.Remote.Mode)
	}

	return &h3Transport{
		h3: &http3.Transport{
			TLSClientConfig: tlsCfg,
			// Cap the QUIC handshake so an upstream that doesn't speak HTTP/3
			// (no UDP listener) fails fast and falls back to TCP, instead of
			// blocking forwarding for the full default ~5s handshake timeout.
			QUICConfig: &quic.Config{HandshakeIdleTimeout: 2 * time.Second},
		},
		fallback: &http.Transport{
			TLSClientConfig:   fallbackTLS,
			ForceAttemptHTTP2: true,
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
		},
		remote:      opts.Remote,
		ea:          ea,
		blocked:     blocked,
		cache:       cache,
		remoteKey:   remoteKey,
		meshLeafURL: meshLeafURL,
		now:         time.Now,
		noH3:        make(map[string]bool),
		pinned:      make(map[verifier.SessionPin]*pinnedTransport),
	}, nil
}

// RoundTrip tries HTTP/3 first; on failure it marks the host and falls back to
// standard HTTP/1.1 or HTTP/2. Connection-level failures (such as a QUIC
// handshake rejection) occur before any request body is consumed, so the
// original request can safely be forwarded via the fallback transport.
//
// Attestation handling is driven entirely by this remote's configured Mode:
//   - AttestNone: forward without attestation.
//   - AttestEndpoint: attest the session against the remote's
//     attestation endpoint before forwarding, and pin traffic to the attested
//     TLS leaf.
//   - any recognised-but-unimplemented mode: fail closed without ever
//     forwarding the request to the unverified backend.
func (t *h3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	if t.ea != nil {
		return t.roundTripEndpoint(req, host)
	}
	if t.blocked != nil {
		return nil, fmt.Errorf("attestation mode %q for %s: %w", t.remote.Mode, host, t.blocked)
	}
	return t.do(req, host)
}

// do performs the actual HTTP/3-then-fallback round trip without any attestation
// handling.
func (t *h3Transport) do(req *http.Request, host string) (*http.Response, error) {
	t.mu.RLock()
	skip := t.noH3[host]
	t.mu.RUnlock()

	var (
		resp *http.Response
		err  error
	)
	if !skip && req.URL.Scheme == "https" {
		resp, err = t.h3.RoundTrip(req)
		if err != nil {
			t.mu.Lock()
			t.noH3[host] = true
			t.mu.Unlock()
		}
	}

	if resp == nil {
		resp, err = t.fallback.RoundTrip(req)
	}
	return resp, err
}

// roundTripEndpoint is the AttestEndpoint path: attest the session against the
// LB's /.well-known/c8s/attest-lb endpoint, then forward over the attested
// upstream TLS. The verdict is scoped to the exact attested serving leaf:
// forwarded traffic must run on a connection presenting the same certificate
// DER, otherwise the session re-attests.
//
// In acme front-door mode the verdict is also scoped to the router's mesh
// leaf, checked before each new forwarding connection and, at most once per
// meshLeafRecheckInterval, before a request on a reused one (transportFor).
// When a check finds a renewed mesh leaf, nothing has been sent: the verdict
// is dropped, and a request whose body is still unread re-attests once and is
// forwarded under the new verdict.
func (t *h3Transport) roundTripEndpoint(req *http.Request, host string) (*http.Response, error) {
	if req.Body == nil || req.Body == http.NoBody {
		resp, err := t.forwardAttested(req, host)
		if errors.Is(err, errMeshLeafChanged) {
			resp, err = t.forwardAttested(req, host)
		}
		return resp, err
	}
	guard := &replayGuard{body: req.Body, held: true}
	out := *req
	out.Body = guard
	resp, err := t.forwardAttested(&out, host)
	if errors.Is(err, errMeshLeafChanged) && guard.rewind() {
		return t.forwardAttested(&out, host)
	}
	guard.release()
	return resp, err
}

// forwardAttested decides the session pin, attesting first when no fresh
// verdict is cached, and forwards req over the transport for that pin.
func (t *h3Transport) forwardAttested(req *http.Request, host string) (*http.Response, error) {
	pin, fresh, ok := t.cache.FreshSession(t.remoteKey)
	if fresh && !ok {
		return nil, fmt.Errorf("attestation previously failed for %s", t.remoteKey)
	}
	var attestedAt time.Time
	if !fresh {
		started := t.cache.Now()
		attestedAt = t.now()
		v, err := t.ea.Attest(req.Context())
		if err != nil {
			// A cancelled client request says nothing about the remote.
			if req.Context().Err() == nil {
				t.cache.RecordFailure(t.remoteKey, started, err)
			}
			slog.Warn("attestation verification failed; refusing to forward",
				"mode", t.remote.Mode, "url", req.URL.String(), "error", err)
			return nil, fmt.Errorf("attestation verification failed for %s: %w", host, err)
		}
		pin = verifier.SessionPin{Leaf: v.LeafSHA256, MeshLeaf: v.MeshLeafSHA256}
		notAfter := v.LeafNotAfter
		if !v.MeshLeafNotAfter.IsZero() && (notAfter.IsZero() || v.MeshLeafNotAfter.Before(notAfter)) {
			notAfter = v.MeshLeafNotAfter
		}
		if !t.cache.RecordPass(t.remoteKey, started, pin, notAfter) {
			// A later attestation failed: refuse. A later pass leaves this
			// verified leaf usable.
			if _, fresh, ok := t.cache.FreshSession(t.remoteKey); fresh && !ok {
				return nil, fmt.Errorf("attestation previously failed for %s", t.remoteKey)
			}
		}
		slog.Info("attestation verified", "mode", t.remote.Mode, "url", req.URL.String(),
			"measurement", v.Measurement, "trust", v.TrustMode, "route_digest", v.RouteDigest, "route_check", v.RouteCheck, "route_revision", v.RouteRevision,
			"policy_check", v.PolicyCheck, "partial", v.Partial, "not_proven", v.NotProven)
	}
	if pin.Leaf == ([32]byte{}) {
		// Unreachable via either branch above, and deliberately fatal rather
		// than defensive: forwarding without a decided pin is the one thing
		// this path must never do.
		return nil, fmt.Errorf("attestation binding for %s: no attested leaf to pin the forwarding handshake to", host)
	}

	// Forward over a transport pinned to THIS request's decided leaves (HTTP/1.1
	// or H2, so resp.TLS reliably carries the peer leaf; attested sessions do
	// not use HTTP/3). The pin travels with the transport rather than being
	// re-read from the cache during the handshake, so a concurrent Invalidate
	// or TTL expiry cannot turn this request's handshake permissive between the
	// FreshSession read above and the dial below.
	pt := t.pinnedFor(pin)
	if !attestedAt.IsZero() {
		// The bundle just verified carried the router's mesh leaf as of then,
		// so that counts as a check; the first dial checks again anyway.
		pt.observe(attestedAt, nil)
	}
	// A request that reuses a connection is not dialed, so it is covered by
	// the pre-forward check: a no-op while the last check is fresh.
	err := pt.recheck(req.Context(), t.now)
	var resp *http.Response
	if err == nil {
		resp, err = pt.tr.RoundTrip(req)
	}
	if errors.Is(err, errMeshLeafChanged) || errors.Is(err, errMeshLeafUnverified) {
		// The check refused the request (before the round trip, or in the
		// dial) before any byte of req was written.
		t.cache.Invalidate(t.remoteKey)
		t.dropPinned(pin)
		slog.Warn("router mesh leaf check failed; dropping the verdict",
			"mode", t.remote.Mode, "url", req.URL.String(), "error", err)
		return nil, fmt.Errorf("attestation binding for %s: %w", host, err)
	}
	if err != nil || resp == nil {
		return resp, err
	}

	// Pin: the serving connection must present the exact attested leaf. A
	// swapped or rotated upstream leaf forces re-attestation rather than silent
	// reuse. New connections are already refused at handshake time
	// (pinnedLeafVerifier); this response-time check is the belt to that
	// braces.
	if !sessionLeafMatches(resp, pin.Leaf) {
		_ = resp.Body.Close()
		t.cache.Invalidate(t.remoteKey)
		t.dropPinned(pin)
		slog.Warn("upstream TLS leaf changed since attestation; dropping response",
			"mode", t.remote.Mode, "url", req.URL.String())
		return nil, fmt.Errorf("attestation binding broken for %s: upstream TLS leaf changed (re-attest required)", host)
	}
	return resp, nil
}

// replayGuard wraps a request body for a forwarding attempt that may be
// repeated. While held, Close is deferred: http.Transport closes the body of
// a request whose dial failed, and the retry needs it open. A body that has
// been read from is never replayed.
type replayGuard struct {
	body io.ReadCloser

	mu          sync.Mutex
	read        bool
	held        bool
	closeCalled bool
}

func (g *replayGuard) Read(p []byte) (int, error) {
	g.mu.Lock()
	g.read = true
	g.mu.Unlock()
	return g.body.Read(p)
}

func (g *replayGuard) Close() error {
	g.mu.Lock()
	if g.held {
		g.closeCalled = true
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()
	return g.body.Close()
}

// rewind reports whether the body is unread and so can be sent again, and
// stops holding Close. On true the next attempt owns the body, so a deferred
// Close is discarded; on false it runs.
func (g *replayGuard) rewind() bool {
	g.mu.Lock()
	unread := !g.read
	if unread {
		g.held, g.closeCalled = false, false
	}
	g.mu.Unlock()
	if !unread {
		g.release()
	}
	return unread
}

// release stops holding Close and runs a Close that was deferred.
func (g *replayGuard) release() {
	g.mu.Lock()
	closeCalled := g.held && g.closeCalled
	g.held = false
	g.closeCalled = false
	g.mu.Unlock()
	if closeCalled {
		_ = g.body.Close()
	}
}

// transportFor returns the forwarding transport for one pin (pinnedFor).
func (t *h3Transport) transportFor(pin verifier.SessionPin) *http.Transport {
	return t.pinnedFor(pin).tr
}

// pinnedFor returns the forwarding transport for one pin, building it on
// first use by cloning the base fallback transport (so the remote's SNI,
// timeouts and any operator trust anchors carry over) and replacing its
// handshake check with a pin on exactly the attested serving leaf. Transports
// are kept per pin so a pooled connection is only ever reused by a request
// that decided on the same certificates.
//
// When the pin names a mesh leaf other than the serving leaf (acme front-door
// mode), the router's current mesh leaf is fetched and compared with the pin
// (checkMeshLeaf) before every new connection is dialed, and before a request
// on a reused connection when the last check is older than
// meshLeafRecheckInterval (recheck). The expected mesh leaf travels with the
// transport, like the serving-leaf pin, so no cache state can relax it.
func (t *h3Transport) pinnedFor(pin verifier.SessionPin) *pinnedTransport {
	t.pinnedMu.Lock()
	defer t.pinnedMu.Unlock()
	if pt, ok := t.pinned[pin]; ok {
		return pt
	}
	tr := t.fallback.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.VerifyConnection = pinnedLeafVerifier(pin.Leaf)
	pt := &pinnedTransport{tr: tr}
	if pin.MeshLeafSeparate() {
		// The fetch runs on its own connection: nginx closes the connection
		// after serving meshLeafPath (keepalive_timeout 0 there), so it cannot
		// share the forwarding one. The probe is pinned to the same serving
		// leaf and speaks HTTP/1.1 only.
		probeTLS := tr.TLSClientConfig.Clone()
		probeTLS.NextProtos = nil
		probe := &http.Transport{
			TLSClientConfig:       probeTLS,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   meshLeafCheckTimeout,
			ResponseHeaderTimeout: meshLeafCheckTimeout,
		}
		meshLeafURL := t.meshLeafURL
		pt.check = func(ctx context.Context) error {
			return checkMeshLeaf(ctx, probe, meshLeafURL, pin)
		}
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		now := t.now
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := pt.checkNow(ctx, now); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}
	t.pinned[pin] = pt
	return pt
}

// recheck is the pre-forward check: it runs check unless the last passing
// observation is younger than meshLeafRecheckInterval, with one check in
// flight per pin. It returns the pin's recorded failure, if any.
func (p *pinnedTransport) recheck(ctx context.Context, now func() time.Time) error {
	if p.check == nil {
		return nil
	}
	p.flight.Lock()
	defer p.flight.Unlock()
	p.mu.Lock()
	failed, checkedAt := p.failed, p.checkedAt
	p.mu.Unlock()
	if failed != nil {
		return failed
	}
	if age := now().Sub(checkedAt); !checkedAt.IsZero() && age >= 0 && age < meshLeafRecheckInterval {
		return nil
	}
	return p.checkNow(ctx, now)
}

// checkNow runs check and records its outcome. A request cancelled by its
// client says nothing about the router: its error is returned unrecorded.
func (p *pinnedTransport) checkNow(ctx context.Context, now func() time.Time) error {
	at := now()
	err := p.check(ctx)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	p.observe(at, err)
	return err
}

// observe records a check that began at at: a pass moves checkedAt forward,
// a failure is kept for good.
func (p *pinnedTransport) observe(at time.Time, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case err != nil:
		if p.failed == nil {
			p.failed = err
		}
	case at.After(p.checkedAt):
		p.checkedAt = at
	}
}

// checkMeshLeaf fetches the router's current mesh leaf over a connection
// pinned to pin.Leaf and compares the first PEM block's SHA-256 with
// pin.MeshLeaf. It returns errMeshLeafChanged on a different leaf and
// errMeshLeafUnverified when the leaf cannot be read.
func checkMeshLeaf(ctx context.Context, probe http.RoundTripper, meshLeafURL string, pin verifier.SessionPin) error {
	ctx, cancel := context.WithTimeout(ctx, meshLeafCheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meshLeafURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", errMeshLeafUnverified, err)
	}
	resp, err := probe.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("%w: fetch %s: %v", errMeshLeafUnverified, meshLeafPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %d", errMeshLeafUnverified, meshLeafPath, resp.StatusCode)
	}
	if !sessionLeafMatches(resp, pin.Leaf) {
		return fmt.Errorf("%w: %s was not served over the attested serving leaf", errMeshLeafUnverified, meshLeafPath)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMeshLeafPEM+1))
	if err != nil {
		return fmt.Errorf("%w: read %s: %v", errMeshLeafUnverified, meshLeafPath, err)
	}
	if len(body) > maxMeshLeafPEM {
		return fmt.Errorf("%w: %s is larger than %d bytes", errMeshLeafUnverified, meshLeafPath, maxMeshLeafPEM)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%w: %s holds no PEM certificate", errMeshLeafUnverified, meshLeafPath)
	}
	got := sha256.Sum256(block.Bytes)
	if subtle.ConstantTimeCompare(got[:], pin.MeshLeaf[:]) != 1 {
		return errMeshLeafChanged
	}
	return nil
}

// dropPinned retires the transport for a pin that is no longer attested,
// closing its pooled connections so nothing survives the invalidation.
func (t *h3Transport) dropPinned(pin verifier.SessionPin) {
	t.pinnedMu.Lock()
	pt, ok := t.pinned[pin]
	delete(t.pinned, pin)
	t.pinnedMu.Unlock()
	if ok {
		pt.tr.CloseIdleConnections()
	}
}

// pinnedLeafVerifier is the handshake-time check for one decided leaf: every
// new TLS handshake (VerifyConnection also runs on resumptions) must present
// that exact certificate DER — not merely the same key, so a substituted
// certificate reusing the attested key fails — aborting before any application
// data is written. It compares against the pin its caller decided on and has no
// permissive branch: there is no cache state that can make it admit a
// certificate it was not built for.
func pinnedLeafVerifier(leaf [32]byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("attestation binding: upstream presented no certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(got[:], leaf[:]) != 1 {
			return fmt.Errorf("attestation binding: upstream TLS leaf does not match the attested leaf certificate (re-attest required)")
		}
		return nil
	}
}

// sessionLeafMatches reports whether the response's TLS peer leaf DER equals
// the attested one (constant-time).
func sessionLeafMatches(resp *http.Response, want [32]byte) bool {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return false
	}
	got := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// Close releases resources held by the H3, fallback and per-leaf transports.
func (t *h3Transport) Close() error {
	t.pinnedMu.Lock()
	for pin, pt := range t.pinned {
		pt.tr.CloseIdleConnections()
		delete(t.pinned, pin)
	}
	t.pinnedMu.Unlock()
	if err := t.h3.Close(); err != nil {
		return err
	}
	t.fallback.CloseIdleConnections()
	return nil
}
