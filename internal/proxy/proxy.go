package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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
type h3Transport struct {
	h3       *http3.Transport
	fallback *http.Transport

	// attestation enforcement (per-remote, independent of other tunnels)
	remote    config.Remote
	ea        *verifier.EndpointAttester // attest-lb mode: active per-handshake attester
	blocked   error                      // set for recognised-but-unimplemented modes: fail closed without forwarding
	cache     *verifier.SessionCache
	remoteKey string

	mu   sync.RWMutex
	noH3 map[string]bool

	// pinnedMu guards pinned, the per-leaf forwarding transports built by
	// transportFor. Keying the connection pool by pin is what makes the
	// handshake check answerable from the request alone: a pooled connection
	// can only ever be reused by a request that decided on the same leaf.
	pinnedMu sync.Mutex
	pinned   map[[32]byte]*http.Transport
}

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
		ea        *verifier.EndpointAttester
		blocked   error
		cache     *verifier.SessionCache
		remoteKey = target.Host
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
		var allowlistDigest []byte
		if opts.Remote.AllowlistPath != "" {
			raw, err := os.ReadFile(opts.Remote.AllowlistPath)
			if err != nil {
				return nil, fmt.Errorf("attest-lb: read pinned allowlist: %w", err)
			}
			sum := sha256.Sum256(raw)
			allowlistDigest = sum[:]
		}
		var imageManifestDigest []byte
		if opts.Remote.ImageManifestPath != "" {
			raw, err := os.ReadFile(opts.Remote.ImageManifestPath)
			if err != nil {
				return nil, fmt.Errorf("attest-lb: read pinned image manifest: %w", err)
			}
			sum := sha256.Sum256(raw)
			imageManifestDigest = sum[:]
		}
		remoteKey = verifier.RemoteKey(target.Host, opts.Remote, allowlistDigest, imageManifestDigest, pinnedCAs)
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
		remote:    opts.Remote,
		ea:        ea,
		blocked:   blocked,
		cache:     cache,
		remoteKey: remoteKey,
		noH3:      make(map[string]bool),
		pinned:    make(map[[32]byte]*http.Transport),
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
func (t *h3Transport) roundTripEndpoint(req *http.Request, host string) (*http.Response, error) {
	leaf, fresh, ok := t.cache.FreshSession(t.remoteKey)
	if fresh && !ok {
		return nil, fmt.Errorf("attestation previously failed for %s", t.remoteKey)
	}
	if !fresh {
		v, err := t.ea.Attest(req.Context())
		var pinned [32]byte
		var notAfter time.Time
		if v != nil {
			pinned = v.LeafSHA256
			notAfter = v.LeafNotAfter
		}
		t.cache.RecordSession(t.remoteKey, err == nil, pinned, notAfter, err)
		if err != nil {
			slog.Warn("attestation verification failed; refusing to forward",
				"mode", t.remote.Mode, "url", req.URL.String(), "error", err)
			return nil, fmt.Errorf("attestation verification failed for %s: %w", host, err)
		}
		slog.Info("attestation verified", "mode", t.remote.Mode, "url", req.URL.String(),
			"measurement", v.Measurement, "trust", v.TrustMode)
		leaf = pinned
	}
	if leaf == ([32]byte{}) {
		// Unreachable via either branch above, and deliberately fatal rather
		// than defensive: forwarding without a decided pin is the one thing
		// this path must never do.
		return nil, fmt.Errorf("attestation binding for %s: no attested leaf to pin the forwarding handshake to", host)
	}

	// Forward over a transport pinned to THIS request's decided leaf (HTTP/1.1
	// or H2, so resp.TLS reliably carries the peer leaf; attested sessions do
	// not use HTTP/3). The pin travels with the transport rather than being
	// re-read from the cache during the handshake, so a concurrent Invalidate
	// or TTL expiry cannot turn this request's handshake permissive between the
	// FreshSession read above and the dial below.
	resp, err := t.transportFor(leaf).RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Pin: the serving connection must present the exact attested leaf. A
	// swapped or rotated upstream leaf forces re-attestation rather than silent
	// reuse. New connections are already refused at handshake time
	// (pinnedLeafVerifier); this response-time check is the belt to that
	// braces.
	if !sessionLeafMatches(resp, leaf) {
		_ = resp.Body.Close()
		t.cache.Invalidate(t.remoteKey)
		t.dropPinned(leaf)
		slog.Warn("upstream TLS leaf changed since attestation; dropping response",
			"mode", t.remote.Mode, "url", req.URL.String())
		return nil, fmt.Errorf("attestation binding broken for %s: upstream TLS leaf changed (re-attest required)", host)
	}
	// A pinned-allowlist c8s router refuses a connection opened before its
	// rollout bound widened. Retire the pooled connection and the verdict so
	// the next request re-attests on a new connection.
	if isFenceRefusal(resp) {
		t.cache.Invalidate(t.remoteKey)
		t.dropPinned(leaf)
		slog.Warn("router fenced this connection after an allowlist change; re-attesting on the next request",
			"mode", t.remote.Mode, "url", req.URL.String())
	}
	return resp, nil
}

// fenceRefusal is the body prefix of a c8s router's fence 503.
const fenceRefusal = "the allowlist bound changed"

// isFenceRefusal reports whether resp is a c8s router's fence 503. It peeks
// at the body and puts the bytes back for the caller.
func isFenceRefusal(resp *http.Response) bool {
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Body == nil {
		return false
	}
	head, _ := io.ReadAll(io.LimitReader(resp.Body, int64(len(fenceRefusal))))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	return string(head) == fenceRefusal
}

// transportFor returns the forwarding transport for one attested leaf,
// building it on first use by cloning the base fallback transport (so the
// remote's SNI, timeouts and any operator trust anchors carry over) and
// replacing its handshake check with a pin on exactly that leaf. Transports are
// kept per leaf so a pooled connection is only ever reused by a request that
// decided on the same certificate.
func (t *h3Transport) transportFor(leaf [32]byte) *http.Transport {
	t.pinnedMu.Lock()
	defer t.pinnedMu.Unlock()
	if tr, ok := t.pinned[leaf]; ok {
		return tr
	}
	tr := t.fallback.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.VerifyConnection = pinnedLeafVerifier(leaf)
	t.pinned[leaf] = tr
	return tr
}

// dropPinned retires the transport for a leaf that is no longer attested,
// closing its pooled connections so nothing survives the invalidation.
func (t *h3Transport) dropPinned(leaf [32]byte) {
	t.pinnedMu.Lock()
	tr, ok := t.pinned[leaf]
	delete(t.pinned, leaf)
	t.pinnedMu.Unlock()
	if ok {
		tr.CloseIdleConnections()
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
	for leaf, tr := range t.pinned {
		tr.CloseIdleConnections()
		delete(t.pinned, leaf)
	}
	t.pinnedMu.Unlock()
	if err := t.h3.Close(); err != nil {
		return err
	}
	t.fallback.CloseIdleConnections()
	return nil
}
