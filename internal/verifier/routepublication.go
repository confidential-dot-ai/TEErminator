package verifier

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/routes"
)

// wellKnownRoutes is where a c8s router publishes its applied signed route
// manifest when route publication is enabled.
const wellKnownRoutes = "/.well-known/c8s/routes"

// maxPublicationBytes bounds a publication response, as c8s does.
const maxPublicationBytes = 4 << 20

// Route checks a verdict can carry in RouteCheck.
const (
	// RoutePinned means the attested digest matched a route_digests pin.
	RoutePinned = "pinned"
	// RouteOperatorSigned means the attested digest matched a published
	// manifest signed under a route_operator_keys key.
	RouteOperatorSigned = "operator-signed"
	// RouteUnverified means no route check is configured: the digest is
	// reported, not checked.
	RouteUnverified = "unverified"
)

// routeCheck validates a remote's route pins and returns its operator keys,
// nil without any. route_digests and route_operator_keys are each a complete
// route check, so setting both is a configuration error.
func routeCheck(r config.Remote) ([]*ecdsa.PublicKey, error) {
	if len(r.RouteDigests) > 0 && len(r.RouteOperatorKeys) > 0 {
		return nil, errors.New("route_digests and route_operator_keys are mutually exclusive: each is a complete route check; keep one")
	}
	if err := ValidateRouteDigests(r.RouteDigests); err != nil {
		return nil, fmt.Errorf("route_digests: %w", err)
	}
	var keys []*ecdsa.PublicKey
	for i, e := range r.RouteOperatorKeys {
		k, err := routes.ParsePublicKeys([]byte(e))
		if err != nil {
			return nil, fmt.Errorf("route_operator_keys[%d]: %w", i, err)
		}
		keys = append(keys, k...)
	}
	return keys, nil
}

// errRouteMismatch reports a published manifest whose digest differs from the
// attested one after the re-fetch.
var errRouteMismatch = errors.New("route digest mismatch")

// publication is the outcome of one publication fetch and check.
type publication struct {
	signed *routes.Signed
	err    error
}

// fetchPublication starts the publication fetch alongside the attest-lb
// handshake. It stops when ctx is done; the buffered channel lets it finish
// even when nobody reads the result.
func (e *EndpointAttester) fetchPublication(ctx context.Context, keys []*ecdsa.PublicKey) <-chan publication {
	ch := make(chan publication, 1)
	go func() {
		s, err := e.publishedRoutes(ctx, keys)
		ch <- publication{s, err}
	}()
	return ch
}

// checkPublishedRoutes requires the published manifest, fetched before the
// handshake verified, to have the attested digest. The publication may come
// from another replica than the handshake, so on a mismatch it fetches once
// more on a new connection and takes that manifest if its digest matches.
// The manifest it takes must pass the attester's revision floor, which then
// rises to it.
func (e *EndpointAttester) checkPublishedRoutes(ctx context.Context, keys []*ecdsa.PublicKey, attested [RouteDigestSize]byte, first publication) (*routes.Signed, error) {
	if first.err != nil {
		return nil, first.err
	}
	s := first.signed
	if s.Digest != attested {
		// A new connection may reach another replica behind an L4 balancer.
		// The attester's transports speak HTTP/1.1, so the re-fetch cannot
		// share the handshake's still-open connection.
		e.client.CloseIdleConnections()
		again, err := e.publishedRoutes(ctx, keys)
		if err != nil {
			return nil, fmt.Errorf("%w: the router attests %x, the published manifest revision %d has %x, and the re-fetch failed: %w", errRouteMismatch, attested, s.Manifest.Revision, s.Digest, err)
		}
		if again.Digest != attested {
			return nil, fmt.Errorf("%w: the router attests %x, the published manifests revisions %d and %d have %x and %x; retry once every router replica has applied the same manifest", errRouteMismatch, attested, s.Manifest.Revision, again.Manifest.Revision, s.Digest, again.Digest)
		}
		s = again
	}
	// The proxy sends the remote URL host as Host, and the router selects
	// routes by it, so a manifest without that host routes no request.
	if !s.Manifest.Routes(e.attestURL.Host) {
		return nil, fmt.Errorf("the operator-signed route manifest revision %d has no routes for host %q: the router would answer every request with 404; route the host in the manifest or fix the remote URL", s.Manifest.Revision, e.attestURL.Hostname())
	}
	if err := e.routeFloor.Accept(s); err != nil {
		action := "two manifests were signed under the same revision; sign the intended one under a higher revision"
		if rb, ok := errors.AsType[*routes.RollbackError](err); ok {
			action = fmt.Sprintf("a router replica may not have applied revision %d yet; retry after the rollout. If this persists, the router serves an older manifest than this tunnel accepted; to roll back on purpose, sign the old routes under a higher revision", rb.Accepted)
		}
		return nil, fmt.Errorf("published route manifest (digest %s): %w: %s", hex.EncodeToString(s.Digest[:]), err, action)
	}
	return s, nil
}

// publishedRoutes fetches the publication and runs the signature and schema
// checks. The fetch needs no transport trust: the operator
// signature authenticates the manifest, and the transcript binds its digest.
func (e *EndpointAttester) publishedRoutes(ctx context.Context, keys []*ecdsa.PublicKey) (*routes.Signed, error) {
	u := *e.attestURL
	u.Path, u.RawQuery = wellKnownRoutes, ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build route publication request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch route publication: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("error closing response Body", "error", err)
		}
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("GET %s returned 404: the router publishes no route manifest (publication off, or none applied yet); enable route publication on the router or pin --route-digest (route_digests) instead", wellKnownRoutes)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GET %s returned %d: %s", wellKnownRoutes, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPublicationBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read route publication: %w", err)
	}
	if len(data) > maxPublicationBytes {
		return nil, fmt.Errorf("route publication exceeds %d bytes", maxPublicationBytes)
	}
	env, err := routes.ParseEnvelope(data)
	if err != nil {
		return nil, err
	}
	s, err := routes.VerifySigned(env, keys)
	if err != nil {
		return nil, fmt.Errorf("the published route manifest does not verify under route_operator_keys: %w", err)
	}
	return s, nil
}
