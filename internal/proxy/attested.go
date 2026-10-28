package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// maxWindowConns caps a window's connections below the router's per-client
// attest-lb burst (20), so a window that opens under load queues requests
// rather than drawing 429s.
const maxWindowConns = 16

// bindingRefusals are the codes the router refuses a request with when the
// attest-lb binding of its connection no longer holds: the route manifest or
// the router's allowlist digest changed, or the binding lapsed.
var bindingRefusals = map[string]bool{
	"route_digest_changed":  true,
	"router_digest_changed": true,
	"binding_expired":       true,
}

// maxRefusalBytes bounds the body read to recognise a binding refusal.
const maxRefusalBytes = 64

// attestedForwarder forwards an attest-lb remote's requests over connections
// that each passed attest-lb on themselves before carrying one, so the router
// binds every connection to the route and router digests its attestation
// verified.
type attestedForwarder struct {
	// dial opens a connection and attests it (verifier.EndpointAttester.Dial).
	dial     func(context.Context) (*tls.Conn, *verifier.SessionVerdict, error)
	remote   string // the remote URL, for logs
	failures *verifier.FailureMemo
	key      string // the remote's failure-memo key
	reattest time.Duration
	now      func() time.Time

	mu sync.Mutex
	// window holds the connections new requests ride.
	window *connWindow
}

// connWindow is a transport whose connections new requests ride until the
// window expires or is retired; requests in flight on it finish there.
type connWindow struct {
	transport *http.Transport

	mu sync.Mutex
	// expires is when new requests stop riding the window: reattest after it
	// opened, or the earliest expiry of a serving leaf it attested.
	expires time.Time
}

func newAttestedForwarder(target *url.URL, opts Options) (*attestedForwarder, error) {
	tlsCfg, err := upstreamTLSConfig(target, opts.Remote, opts.ExtraCAs)
	if err != nil {
		return nil, err
	}
	pinnedCAs, err := parseExtraCAs(opts.ExtraCAs)
	if err != nil {
		return nil, err
	}
	// The key covers the endpoint mode and every policy pin, so a failure
	// remembered under one policy never refuses traffic under another.
	files, err := verifier.PinnedFileDigests(opts.Remote)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}
	// The handshake captures the serving leaf before its attested mode is
	// known; the attester then requires a mesh-CA chain in cds mode, or WebPKI
	// name and chain validation against RootCAs in acme mode, and binds the
	// exact serving-leaf DER into fresh hardware evidence.
	attestTLS := &tls.Config{
		ServerName:         tlsCfg.ServerName,
		RootCAs:            tlsCfg.RootCAs,
		InsecureSkipVerify: true,
	}
	ea, err := verifier.NewEndpointAttester(target, attestTLS, opts.Remote, pinnedCAs)
	if err != nil {
		return nil, err
	}
	f := &attestedForwarder{
		dial:     ea.Dial,
		remote:   opts.Remote.Remote,
		failures: verifier.NewFailureMemo(opts.ReattestInterval),
		key:      verifier.RemoteKey(target.Host, opts.Remote, files, pinnedCAs),
		reattest: opts.ReattestInterval,
		now:      time.Now,
	}
	f.window = f.newWindow()
	return f, nil
}

// RoundTrip sends req on an attested connection of the current window. A
// binding refusal is returned to the caller as the router sent it, and
// retires the window.
func (f *attestedForwarder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("attest-lb forwards only over https, not %s", req.URL.Scheme)
	}
	if err := f.failures.Failed(f.key); err != nil {
		return nil, fmt.Errorf("attestation previously failed for %s: %w", req.URL.Host, err)
	}
	w := f.currentWindow()
	resp, err := w.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	code, err := bindingRefusal(resp)
	if err != nil {
		return nil, err
	}
	if code != "" {
		f.retire(w)
		slog.Info("the router ended an attested connection's binding; new requests attest new connections",
			"code", code, "url", req.URL.String())
	}
	return resp, nil
}

// Close closes the current window's idle connections.
func (f *attestedForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.window.transport.CloseIdleConnections()
	return nil
}

// currentWindow returns the window new requests ride, opening a new one once
// the current one has expired.
func (f *attestedForwarder) currentWindow() *connWindow {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.window.expiredAt(f.now()) {
		f.replaceWindowLocked()
	}
	return f.window
}

// retire moves new requests to a new window, unless w was replaced already.
func (f *attestedForwarder) retire(w *connWindow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.window == w {
		f.replaceWindowLocked()
	}
}

// retireCurrent moves new requests to a new window.
func (f *attestedForwarder) retireCurrent() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceWindowLocked()
}

func (f *attestedForwarder) replaceWindowLocked() {
	f.window.transport.CloseIdleConnections()
	f.window = f.newWindow()
}

// newWindow opens a window whose every connection comes from dialAttested.
// With a zero interval each connection carries one request.
func (f *attestedForwarder) newWindow() *connWindow {
	w := &connWindow{expires: f.now().Add(f.reattest)}
	// INVARIANT: RoundTrip sends only https requests, and there is no Proxy
	// and no HTTP/2, so every connection a request rides is one dialAttested
	// returned.
	w.transport = &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return f.dialAttested(ctx, w)
		},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxConnsPerHost:     maxWindowConns,
		MaxIdleConnsPerHost: maxWindowConns,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   f.reattest == 0,
	}
	return w
}

// dialAttested returns a connection attest-lb passed on, for window w. A
// failed verification is remembered and retires the current window.
func (f *attestedForwarder) dialAttested(ctx context.Context, w *connWindow) (net.Conn, error) {
	if err := f.failures.Failed(f.key); err != nil {
		return nil, fmt.Errorf("attestation previously failed for %s: %w", f.remote, err)
	}
	started := f.failures.Now()
	conn, v, err := f.dial(ctx)
	if err != nil {
		if judgedTheRemote(ctx, err) {
			f.failures.RecordFailure(f.key, started, err)
			f.retireCurrent()
		}
		slog.Warn("attestation failed; refusing to forward", "url", f.remote, "error", err)
		return nil, fmt.Errorf("attestation failed for %s: %w", f.remote, err)
	}
	if later := f.failures.RecordPass(f.key, started); later != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("attestation previously failed for %s: %w", f.remote, later)
	}
	w.endBy(v.LeafNotAfter)
	slog.Info("attestation verified", "url", f.remote,
		"measurement", v.Measurement, "trust", v.TrustMode, "route_digest", v.RouteDigest, "route_check", v.RouteCheck, "route_revision", v.RouteRevision,
		"policy_check", v.PolicyCheck, "partial", v.Partial, "not_proven", v.NotProven)
	return conn, nil
}

// judgedTheRemote reports whether a failed dial is a verdict on the remote:
// not a router that could not attest now, and not a dial net/http abandoned.
func judgedTheRemote(ctx context.Context, err error) bool {
	return !errors.Is(err, verifier.ErrUnavailable) && ctx.Err() == nil
}

// expiredAt reports whether new requests stop riding w by now.
func (w *connWindow) expiredAt(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !now.Before(w.expires)
}

// endBy brings w's expiry forward to t if t is earlier.
func (w *connWindow) endBy(t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t.Before(w.expires) {
		w.expires = t
	}
}

// bindingRefusal returns the code of resp when it is the router refusing its
// request for a binding that no longer holds, and "" otherwise. It reads at
// most maxRefusalBytes+1 bytes of a 503 body, and leaves resp.Body readable
// from the start.
func bindingRefusal(resp *http.Response) (string, error) {
	if !mayBeBindingRefusal(resp) {
		return "", nil
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, maxRefusalBytes+1))
	if err != nil {
		_ = resp.Body.Close()
		return "", err
	}
	resp.Body = replayingBody(head, resp.Body)
	return refusalCode(head), nil
}

// replayingBody returns body with head, already read from it, put back in
// front: reads return head and then the rest of body, and Close closes body.
func replayingBody(head []byte, body io.ReadCloser) io.ReadCloser {
	return &replayedBody{
		reader: io.MultiReader(bytes.NewReader(head), body),
		body:   body,
	}
}

type replayedBody struct {
	reader io.Reader
	body   io.ReadCloser
}

func (b *replayedBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *replayedBody) Close() error {
	return b.body.Close()
}

// mayBeBindingRefusal reports whether resp is a 503 whose body, of unknown
// length or at most maxRefusalBytes, may be a refusal code.
func mayBeBindingRefusal(resp *http.Response) bool {
	return resp.StatusCode == http.StatusServiceUnavailable && resp.ContentLength <= maxRefusalBytes
}

// refusalCode returns the binding refusal body names in full, or "".
func refusalCode(body []byte) string {
	if len(body) > maxRefusalBytes {
		return ""
	}
	code := strings.TrimSpace(string(body))
	if !bindingRefusals[code] {
		return ""
	}
	return code
}
