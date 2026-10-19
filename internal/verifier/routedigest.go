package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// RouteDigestSize is the byte length of a route digest: the SHA-256 of the
// route manifest the router had applied when it admitted the handshake.
const RouteDigestSize = sha256.Size

// parseRouteDigest decodes exactly 64 lowercase hex characters. Uppercase is
// rejected, as for register pins, so one digest has one spelling.
func parseRouteDigest(s string) ([RouteDigestSize]byte, error) {
	var out [RouteDigestSize]byte
	if len(s) != RouteDigestSize*2 || strings.ToLower(s) != s {
		return out, fmt.Errorf("route digest %q is not %d lowercase hex chars", s, RouteDigestSize*2)
	}
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return out, fmt.Errorf("route digest %q is not %d lowercase hex chars", s, RouteDigestSize*2)
	}
	return out, nil
}

// ValidateRouteDigests checks every pinned route digest's syntax.
func ValidateRouteDigests(pins []string) error {
	for _, p := range pins {
		if _, err := parseRouteDigest(p); err != nil {
			return err
		}
	}
	return nil
}

// checkRouteDigest enforces the pin set on an attested route digest; an empty
// set accepts any digest. Several pins let a client accept the old and the new
// manifest across a route change.
func checkRouteDigest(got string, pins []string) error {
	if len(pins) == 0 || slices.Contains(pins, got) {
		return nil
	}
	return fmt.Errorf("route digest mismatch: the router attests %s, want one of %s; if the route change is expected, add the new digest to the remote's route_digests", got, strings.Join(pins, ", "))
}
