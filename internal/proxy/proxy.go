package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
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
	// ReattestInterval is how long new requests reuse attested connections
	// before attesting new ones, and how long a failed verification is kept.
	// Zero attests a connection per request.
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
	transport forwarder
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

	transport, err := newForwarder(target, opts)
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

// forwarder carries a tunnel's requests to its remote under the remote's
// attestation mode.
type forwarder interface {
	http.RoundTripper
	Close() error
}

// newForwarder returns the forwarder for opts.Remote.Mode.
func newForwarder(target *url.URL, opts Options) (forwarder, error) {
	switch opts.Remote.Mode {
	case config.AttestNone:
		return newH3Transport(target, opts)
	case config.AttestEndpoint:
		return newAttestedForwarder(target, opts)
	case config.AttestCDSCert:
		return refusingForwarder{mode: opts.Remote.Mode}, nil
	default:
		return nil, fmt.Errorf("unknown attestation mode %q", opts.Remote.Mode)
	}
}

// refusingForwarder fails closed for a recognised but unimplemented mode:
// every request is refused without reaching the unverified backend.
type refusingForwarder struct {
	mode config.AttestMode
}

func (f refusingForwarder) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("attestation mode %q for %s: %w (use the c8s-verify-js browser client for this flow today)",
		f.mode, req.URL.Host, verifier.ErrNotImplemented)
}

func (refusingForwarder) Close() error {
	return nil
}

// h3Transport forwards without attestation. It tries HTTP/3 (QUIC) first and
// falls back to standard HTTPS/HTTP. A per-host cache remembers hosts where
// HTTP/3 failed so that subsequent requests skip the QUIC attempt and go
// directly through the fallback.
type h3Transport struct {
	h3       *http3.Transport
	fallback *http.Transport

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
		noH3: make(map[string]bool),
	}, nil
}

// RoundTrip tries HTTP/3 first; on failure it marks the host and falls back to
// standard HTTP/1.1 or HTTP/2. Connection-level failures (such as a QUIC
// handshake rejection) occur before any request body is consumed, so the
// original request can safely be forwarded via the fallback transport.
func (t *h3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
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

// Close releases resources held by the H3 and fallback transports.
func (t *h3Transport) Close() error {
	if err := t.h3.Close(); err != nil {
		return err
	}
	t.fallback.CloseIdleConnections()
	return nil
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
