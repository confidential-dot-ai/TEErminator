package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
type h3Transport struct {
	h3       *http3.Transport
	fallback *http.Transport

	// attestation enforcement (per-remote, independent of other tunnels)
	remote    config.Remote
	ea        *verifier.EndpointAttester // attest mode: active session-start attester
	blocked   error                      // set for recognised-but-unimplemented modes: fail closed without forwarding
	cache     *verifier.SessionCache
	remoteKey string

	mu   sync.RWMutex
	noH3 map[string]bool
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

func newH3Transport(target *url.URL, opts Options) (*h3Transport, error) {
	tlsCfg, err := upstreamTLSConfig(target, opts.Remote, opts.ExtraCAs)
	if err != nil {
		return nil, err
	}

	var (
		ea      *verifier.EndpointAttester
		blocked error
		cache   *verifier.SessionCache
	)
	switch opts.Remote.Mode {
	case config.AttestNone:
		// No attestation: plain forwarding.
	case config.AttestEndpoint:
		// The endpoint attester fetches the attestation bundle itself, over the same TLS trust
		// the proxy uses for the upstream, so the leaf it observes (and binds to)
		// is the one forwarded traffic rides.
		attestClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg.Clone()},
			Timeout:   30 * time.Second,
		}
		baseURL := target.Scheme + "://" + target.Host
		var err error
		ea, err = verifier.NewEndpointAttester(baseURL, attestClient, opts.Remote, tlsCfg.RootCAs)
		if err != nil {
			return nil, err
		}
		cache = verifier.NewSessionCache(opts.ReattestInterval)
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
			TLSClientConfig:   tlsCfg.Clone(),
			ForceAttemptHTTP2: true,
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
		},
		remote:    opts.Remote,
		ea:        ea,
		blocked:   blocked,
		cache:     cache,
		remoteKey: target.Host,
		noH3:      make(map[string]bool),
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

// roundTripEndpoint is the AttestEndpoint path: attest the session
// against the LB's /.well-known/c8s/attestation endpoint at session start, then
// forward over the validated upstream TLS. The verdict is scoped to the attested
// LB leaf (TLS-session scoped TEE binding): forwarded traffic must run on a
// connection presenting the same leaf, otherwise the session re-attests.
func (t *h3Transport) roundTripEndpoint(req *http.Request, host string) (*http.Response, error) {
	spki, fresh, ok := t.cache.FreshSession(t.remoteKey)
	if fresh && !ok {
		return nil, fmt.Errorf("attestation previously failed for %s", t.remoteKey)
	}
	if !fresh {
		v, err := t.ea.Attest(req.Context())
		var pinned [32]byte
		if v != nil {
			pinned = v.LeafSPKI
		}
		t.cache.RecordSession(t.remoteKey, err == nil, pinned, err)
		if err != nil {
			slog.Warn("attestation verification failed; refusing to forward",
				"mode", t.remote.Mode, "url", req.URL.String(), "error", err)
			return nil, fmt.Errorf("attestation verification failed for %s: %w", host, err)
		}
		slog.Info("attestation verified", "mode", t.remote.Mode, "url", req.URL.String(), "measurement", v.Measurement)
		spki = pinned
	}

	// Forward over the fallback transport (HTTP/1.1 or H2) so resp.TLS reliably
	// carries the peer leaf we pin against; attested sessions do not use HTTP/3.
	resp, err := t.fallback.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Pin: the serving connection must present the attested LB leaf. A swapped or
	// rotated upstream leaf forces re-attestation rather than silent reuse.
	if !sessionLeafMatches(resp, spki) {
		_ = resp.Body.Close()
		t.cache.Invalidate(t.remoteKey)
		slog.Warn("upstream TLS leaf changed since attestation; dropping response",
			"mode", t.remote.Mode, "url", req.URL.String())
		return nil, fmt.Errorf("attestation binding broken for %s: upstream TLS leaf changed (re-attest required)", host)
	}
	return resp, nil
}

// sessionLeafMatches reports whether the response's TLS peer leaf SPKI equals the
// attested one (constant-time).
func sessionLeafMatches(resp *http.Response, want [32]byte) bool {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return false
	}
	got := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// Close releases resources held by both transports.
func (t *h3Transport) Close() error {
	if err := t.h3.Close(); err != nil {
		return err
	}
	t.fallback.CloseIdleConnections()
	return nil
}
