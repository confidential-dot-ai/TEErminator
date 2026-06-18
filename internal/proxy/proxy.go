package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	vf        verifier.Verifier
	cache     *verifier.SessionCache
	remoteKey string

	mu   sync.RWMutex
	noH3 map[string]bool
}

func newH3Transport(target *url.URL, opts Options) (*h3Transport, error) {
	// Validate the upstream cert against the configured ServerName when set,
	// otherwise the URL host. The override covers backends reached by an IP (or
	// any name) whose certificate only carries a different SAN.
	serverName := target.Hostname()
	if opts.Remote.ServerName != "" {
		serverName = opts.Remote.ServerName
	}
	tlsCfg := &tls.Config{
		ServerName: serverName,
	}
	// Append any operator-added CAs (`certs add`) to the system trust store so a
	// privately-issued upstream cert (e.g. c8s mesh CA) verifies. With no extra
	// CAs, RootCAs stays nil and the system roots are used unchanged.
	if len(opts.ExtraCAs) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, c := range opts.ExtraCAs {
			if !pool.AppendCertsFromPEM([]byte(c.PEM)) {
				return nil, fmt.Errorf("trust store: failed to parse stored CA %q", c.CommonName)
			}
		}
		tlsCfg.RootCAs = pool
	}

	vf, err := verifier.For(opts.Remote.Mode)
	if err != nil {
		return nil, err
	}
	var cache *verifier.SessionCache
	if vf != nil {
		cache = verifier.NewSessionCache(opts.ReattestInterval)
	}

	return &h3Transport{
		h3: &http3.Transport{
			TLSClientConfig: tlsCfg,
		},
		fallback: &http.Transport{
			TLSClientConfig:   tlsCfg.Clone(),
			ForceAttemptHTTP2: true,
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
		},
		remote:    opts.Remote,
		vf:        vf,
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
//   - AttestNone (nil verifier): legacy best-effort — log any Attestation-Report
//     header without enforcing.
//   - any other mode: enforce that remote's method and fail closed (a
//     verification error drops the response). Any mode that is recognised but not
//     yet implemented therefore blocks traffic rather than forwarding it
//     unverified.
func (t *h3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	if t.vf == nil {
		return t.roundTripLegacy(req, host)
	}

	// If this remote was verified within the re-attest interval, reuse the
	// verdict and skip per-request attestation work — the established TLS session
	// already carries the security guarantee between periodic freshness checks.
	if fresh, ok := t.cache.Fresh(t.remoteKey); fresh {
		if !ok {
			return nil, fmt.Errorf("attestation previously failed for %s", t.remoteKey)
		}
		return t.do(req, host)
	}

	// Flow A binds a fresh per-request nonce into the evidence so a report
	// captured from an earlier session cannot be replayed.
	var nonce []byte
	if t.remote.Mode == config.AttestTLSHeader {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate attestation nonce: %w", err)
		}
		req.Header.Set(verifier.NonceHeader, base64.RawURLEncoding.EncodeToString(nonce))
	}

	resp, err := t.do(req, host)
	if err != nil || resp == nil {
		return resp, err
	}

	// Fail closed: a verification error drops the response.
	res, verifyErr := t.vf.Verify(verifier.Input{
		Remote:           &t.remote,
		Nonce:            nonce,
		ResponseHeader:   resp.Header,
		PeerCertificates: peerCerts(resp),
	})
	t.cache.Record(t.remoteKey, verifyErr == nil, verifyErr)
	if verifyErr != nil {
		_ = resp.Body.Close()
		slog.Warn("attestation verification failed; dropping response",
			"mode", t.remote.Mode, "url", req.URL.String(), "error", verifyErr)
		return nil, fmt.Errorf("attestation verification failed for %s: %w", host, verifyErr)
	}
	slog.Info("attestation verified", "mode", t.remote.Mode, "url", req.URL.String(), "measurement", res.Measurement)
	return resp, nil
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

// roundTripLegacy is the AttestNone path: forward the request and log any
// Attestation-Report header without enforcing a verdict.
func (t *h3Transport) roundTripLegacy(req *http.Request, host string) (*http.Response, error) {
	resp, err := t.do(req, host)
	if err != nil || resp == nil {
		return resp, err
	}
	if reportHeader := resp.Header.Get(verifier.AttestationHeader); reportHeader != "" {
		if verifyErr := verifier.VerifyAzSnpAttestation([]byte(reportHeader)); verifyErr != nil {
			slog.Warn("attestation report verification failed", "url", req.URL.String(), "error", verifyErr)
		} else {
			slog.Info("attestation report verified successfully", "url", req.URL.String())
		}
	}
	return resp, err
}

// peerCerts returns the verified TLS peer chain from a response, if any.
func peerCerts(resp *http.Response) []*x509.Certificate {
	if resp.TLS == nil {
		return nil
	}
	return resp.TLS.PeerCertificates
}

// Close releases resources held by both transports.
func (t *h3Transport) Close() error {
	if err := t.h3.Close(); err != nil {
		return err
	}
	t.fallback.CloseIdleConnections()
	return nil
}
