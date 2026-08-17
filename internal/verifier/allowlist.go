package verifier

// Fetching a cluster's workload allowlist and checking it against what the
// cluster attested.
//
// What this proves, exactly: the hardware evidence binds the mesh leaf into the
// attest-lb transcript, the mesh CA's signature over that leaf vouches for the
// matched-workload stamp inside it, and the stamp names the SHA-256 of the
// allowlist snapshot the workload match was decided under. A document whose
// bytes hash to that digest is therefore the snapshot the attested front door
// was matched against — it is CA-VOUCHED, not hardware-committed. Nothing here
// proves the cluster is *currently* serving that snapshot, only that these
// bytes are the ones the stamp names.
//
// The digest is over the bytes as received. They are never re-encoded: a
// canonical-JSON document that goes through any JSON encoder comes back with
// different bytes and a different digest.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// allowlistRoute is the served allowlist document's path, at the front door's
// origin (the tls-lb proxies it), independent of whatever a remote forwards to.
const allowlistRoute = "/allowlist"

// maxAllowlistBytes caps the served document, mirroring the c8s client's own
// cap: generous for a realistic fleet, bounded so a buggy or hostile front door
// cannot make this process read forever.
const maxAllowlistBytes = 4 << 20

// FetchedAllowlist is a served allowlist document that matched the attested
// front door's matched-workload stamp.
type FetchedAllowlist struct {
	// Raw is EXACTLY the bytes the cluster served. Digest is taken over these,
	// so they are what must be written to disk — re-encoding them, even through
	// a JSON round trip that preserves meaning, produces a file that no longer
	// matches the stamp.
	Raw []byte
	// Digest is SHA-256(Raw), equal to the stamp's allowlist digest.
	Digest [32]byte
	// Workload is the stamped workload name, resolved in this document.
	Workload string
	// StampedVersion is the store version counter the stamp carries.
	StampedVersion string
	// ServedVersion is the store version the response's weak ETag carried, or
	// "" when the header was absent or malformed. Transport metadata, outside
	// the digest: it may only sharpen a diagnosis, never decide one.
	ServedVersion string
}

// AllowlistDigestMismatch reports served (or pinned) allowlist bytes that are
// not the snapshot the stamp names. On a fetch this is operationally normal
// rather than an attack: the stamp names the snapshot the workload match was
// decided under, so an allowlist edited between leaf issuance and the fetch
// legitimately hashes differently.
type AllowlistDigestMismatch struct {
	// StampedDigest is the digest the mesh leaf's stamp names.
	StampedDigest []byte
	// ServedDigest is SHA-256 of the bytes actually received (or read).
	ServedDigest [32]byte
	// StampedVersion is the store version counter the stamp carries.
	StampedVersion string
	// ServedVersion is the version from the response ETag, "" when unknown.
	// Diagnostic only — see FetchedAllowlist.ServedVersion.
	ServedVersion string
}

func (e *AllowlistDigestMismatch) stampedHex() string { return hex.EncodeToString(e.StampedDigest) }
func (e *AllowlistDigestMismatch) servedHex() string  { return hex.EncodeToString(e.ServedDigest[:]) }

func (e *AllowlistDigestMismatch) Error() string {
	return fmt.Sprintf("served allowlist is not the snapshot the mesh leaf's stamp names: stamped digest %s, served digest %s — %s",
		e.stampedHex(), e.servedHex(), e.diagnosis())
}

// diagnosis reads the two version counters to tell the ordinary case (the
// cluster's allowlist moved on since the leaf was issued) apart from the one
// that is not ordinary (the same snapshot claimed for different bytes). The
// served counter rides in the ETag, outside the digest, so a front door can say
// anything it likes here: this only ever picks the wording, never the verdict.
func (e *AllowlistDigestMismatch) diagnosis() string {
	cmp, ok := compareAllowlistVersions(e.ServedVersion, e.StampedVersion)
	switch {
	case ok && cmp > 0:
		return fmt.Sprintf("the cluster's allowlist changed after this leaf was issued (stamped version %s, served version %s); re-run the fetch — a freshly issued leaf names the current snapshot",
			e.StampedVersion, e.ServedVersion)
	case ok && cmp == 0:
		return fmt.Sprintf("the served document claims the SAME version as the stamp (%s) with different bytes, which allowlist churn cannot explain; do not use these bytes, and check what is answering %s for this cluster",
			e.StampedVersion, allowlistRoute)
	case ok:
		return fmt.Sprintf("the served version (%s) is OLDER than the stamped one (%s), so this is not the snapshot moving forward; do not use these bytes, and check what is answering %s for this cluster",
			e.ServedVersion, e.StampedVersion, allowlistRoute)
	default:
		return fmt.Sprintf("the response carried no usable version (stamped version %s, ETag version %q), so churn cannot be told apart from a substituted document; re-run the fetch, and treat a repeat as a substitution",
			e.StampedVersion, e.ServedVersion)
	}
}

// FetchAllowlist fetches baseURL's allowlist document and returns it only when
// it is exactly the snapshot stamp names: SHA-256 over the bytes as received
// must equal the stamp's digest, and the stamped workload must resolve in the
// parsed document. Any other outcome is an error and yields no bytes — a caller
// must never be handed a document that failed the check.
//
// client is the caller's transport; it should be pinned to the attested serving
// leaf, though the digest — not the channel — is what makes the returned bytes
// trustworthy. stamp must come from a chain-verified mesh leaf (SessionVerdict.Stamp).
func FetchAllowlist(ctx context.Context, client *http.Client, baseURL string, stamp *MatchedWorkload) (*FetchedAllowlist, error) {
	if stamp == nil {
		return nil, fmt.Errorf("allowlist fetch: the attested mesh leaf carries no matched-workload stamp, so there is nothing to check a served document against")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("allowlist fetch: parse base URL: %w", err)
	}
	u.Path = allowlistRoute
	u.RawQuery = ""

	// The fetch is not allowed to move: the connection is pinned to the
	// attested leaf, and following a redirect off it would fetch the document
	// from a host the attestation says nothing about. A redirect is surfaced as
	// its own non-200 response instead. The client is copied rather than
	// mutated so a caller's shared client keeps its own policy.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("allowlist fetch: build request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("allowlist fetch: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("error closing response Body", "error", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("allowlist fetch: %s returned %d: %s", u.Path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Checked before the digest so an error page or a captive-portal answer
	// reads as what it is, instead of as a substituted allowlist.
	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return nil, fmt.Errorf("allowlist fetch: unexpected content type %q (want application/json)", ct)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAllowlistBytes+1))
	if err != nil {
		return nil, fmt.Errorf("allowlist fetch: read response: %w", err)
	}
	if len(raw) > maxAllowlistBytes {
		return nil, fmt.Errorf("allowlist fetch: response exceeds %d bytes", maxAllowlistBytes)
	}

	served := versionFromETag(resp.Header.Get("ETag"))
	if err := checkAllowlistBytes(raw, stamp); err != nil {
		var mismatch *AllowlistDigestMismatch
		if errors.As(err, &mismatch) {
			mismatch.ServedVersion = served
			return nil, fmt.Errorf("allowlist fetch: %w", mismatch)
		}
		return nil, fmt.Errorf("allowlist fetch: %w", err)
	}
	return &FetchedAllowlist{
		Raw:            raw,
		Digest:         sha256.Sum256(raw),
		Workload:       stamp.Name,
		StampedVersion: stamp.AllowlistVersion,
		ServedVersion:  served,
	}, nil
}

// checkAllowlistBytes is the one allowlist check in this client, shared by the
// pinned-file path (checkWorkloadPolicy) and the fetch path: SHA-256 over the
// bytes exactly as read or received must equal the stamp's digest, and the
// stamped workload must resolve in the parsed document. Parsing only ever
// resolves the name — the digest is never taken over a reserialization.
func checkAllowlistBytes(raw []byte, stamp *MatchedWorkload) error {
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], stamp.AllowlistDigest) {
		return &AllowlistDigestMismatch{
			StampedDigest:  stamp.AllowlistDigest,
			ServedDigest:   digest,
			StampedVersion: stamp.AllowlistVersion,
		}
	}
	doc, err := ParsePinnedAllowlist(raw)
	if err != nil {
		return err
	}
	if _, ok := doc.Workloads[stamp.Name]; !ok {
		return fmt.Errorf("stamped workload %q does not resolve in the allowlist document", stamp.Name)
	}
	return nil
}

// versionFromETag extracts N from the weak ETag W/"N" c8s derives from the
// store version, or "" when the header is absent or not that shape.
func versionFromETag(etag string) string {
	v, ok := strings.CutPrefix(strings.TrimSpace(etag), `W/"`)
	if !ok {
		return ""
	}
	v, ok = strings.CutSuffix(v, `"`)
	if !ok {
		return ""
	}
	return v
}

// compareAllowlistVersions orders two store version counters the way the
// canonical decimal encoding allows — by length, then lexically. ok is false
// unless both are that encoding, which is the only case a caller may read
// anything into.
func compareAllowlistVersions(a, b string) (int, bool) {
	if !allowlistVersionPattern.MatchString(a) || !allowlistVersionPattern.MatchString(b) {
		return 0, false
	}
	if len(a) != len(b) {
		return len(a) - len(b), true
	}
	return strings.Compare(a, b), true
}

// isJSONContentType reports whether ct is application/json, ignoring
// parameters.
func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}
