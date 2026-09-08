package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// AllowlistFetch is the outcome of a successful allowlist fetch: the verdict of
// the attestation that produced the stamp, and the served document that matched
// it.
type AllowlistFetch struct {
	Verdict *verifier.SessionVerdict
	// Document holds the served bytes and the stamp they matched. Its Raw field
	// is what a caller writes to disk, verbatim.
	Document *verifier.FetchedAllowlist
	// Reattested reports that the first attempt's document did not match the
	// first leaf's stamp and the whole flow was re-run once, successfully.
	Reattested bool
}

// FetchAllowlist attests r's front door, reads the matched-workload stamp off
// the chain-verified mesh leaf, fetches the cluster's allowlist over a
// connection pinned to the attested serving leaf, and returns the document only
// when its bytes hash to the digest the stamp names and the stamped workload
// resolves in it.
//
// The guarantee is CA-vouched, not hardware-committed: the hardware evidence
// binds the mesh leaf into the attest-lb transcript, and the mesh CA's
// signature over that leaf is what vouches for the stamp naming the digest. The
// returned document is the allowlist snapshot the attested front door's
// workload match was decided under — not proof of what the cluster enforces
// now.
//
// A digest mismatch is retried exactly once, from a fresh attestation: the
// ordinary cause is an allowlist edited between leaf issuance and the fetch,
// and a freshly issued leaf names the new snapshot. A second mismatch is
// returned as a *verifier.AllowlistDigestMismatch, whose message tells ordinary
// churn apart from a substituted document.
func FetchAllowlist(ctx context.Context, r config.Remote, extraCAs []config.Cert) (*AllowlistFetch, error) {
	if r.Mode != config.AttestEndpoint {
		return nil, fmt.Errorf("allowlist fetch requires a remote with --mode attest-lb (this one is %q): only the attest-lb handshake yields a mesh leaf whose stamp names the allowlist snapshot a served document can be checked against",
			modeLabel(r.Mode))
	}
	res, err := allowlistAttempt(ctx, r, extraCAs)
	var mismatch *verifier.AllowlistDigestMismatch
	if !errors.As(err, &mismatch) {
		return res, err
	}
	// One automatic re-attest, so the common race — the allowlist changed
	// between the leaf's issuance and this fetch — resolves itself instead of
	// asking the operator to run the same command again. Exactly one: a second
	// mismatch is a standing disagreement, not a race, and the operator needs
	// to see it rather than have the client loop over it.
	retried, retryErr := allowlistAttempt(ctx, r, extraCAs)
	if retryErr != nil {
		var retryMismatch *verifier.AllowlistDigestMismatch
		if errors.As(retryErr, &retryMismatch) {
			return nil, retryErr
		}
		// The retry failed for an unrelated reason; the mismatch is still the
		// answer to report, with the retry's failure named as why it stands.
		return nil, fmt.Errorf("%w (re-attest attempt failed: %v)", err, retryErr)
	}
	retried.Reattested = true
	return retried, nil
}

// allowlistAttempt is one full attest-then-fetch cycle, in a variable so tests
// can drive FetchAllowlist's retry decision without live evidence.
var allowlistAttempt = attemptAllowlistFetch

// attemptAllowlistFetch attests once and fetches the allowlist over that
// attestation's leaf.
func attemptAllowlistFetch(ctx context.Context, r config.Remote, extraCAs []config.Cert) (*AllowlistFetch, error) {
	target, err := url.Parse(r.Remote)
	if err != nil {
		return nil, fmt.Errorf("invalid remote URL: %w", err)
	}
	origin := target.Scheme + "://" + target.Host

	pinnedCAs, err := parseExtraCAs(extraCAs)
	if err != nil {
		return nil, err
	}
	// Capture the serving leaf first. In cds mode the serving leaf must chain
	// to the committed mesh CA. In acme mode WebPKI verification proves only
	// the certificate's name and issuance — it does not by itself prove the
	// serving key is TEE-held. That proof comes from the hardware evidence:
	// the exact serving-leaf DER is bound into report_data, the front-door
	// mode is part of the attested transcript, and host-visible `webpki`
	// secrets are rejected there. No application data is sent before the
	// verdict.
	webPKITLS, err := upstreamTLSConfig(target, r, extraCAs)
	if err != nil {
		return nil, err
	}
	attestTLS := webPKITLS.Clone()
	attestTLS.InsecureSkipVerify = true // trust is checked after the mode is attested
	attestTr := &http.Transport{TLSClientConfig: attestTLS}
	defer attestTr.CloseIdleConnections()

	ea, err := verifier.NewEndpointAttester(origin, &http.Client{Transport: attestTr}, r, pinnedCAs, webPKITLS.RootCAs)
	if err != nil {
		return nil, err
	}
	v, err := ea.Attest(ctx)
	if err != nil {
		return nil, err
	}
	if v.Stamp == nil {
		return nil, fmt.Errorf("the attested mesh leaf carries no matched-workload stamp: this front door does not stamp the allowlist snapshot it matched, so a fetched document cannot be checked against anything")
	}

	// Fetch over the leaf the evidence bound. The digest check is what makes
	// the bytes trustworthy, so this pin is not what proves them — it keeps the
	// fetch on the endpoint that was actually attested, the same way forwarded
	// traffic is kept there.
	fetchTLS := attestTLS.Clone()
	fetchTLS.VerifyConnection = pinnedLeafVerifier(v.LeafSHA256)
	fetchTr := &http.Transport{TLSClientConfig: fetchTLS}
	defer fetchTr.CloseIdleConnections()

	doc, err := verifier.FetchAllowlist(ctx, &http.Client{Transport: fetchTr}, origin, v.Stamp)
	if err != nil {
		return nil, err
	}
	return &AllowlistFetch{Verdict: v, Document: doc}, nil
}

// modeLabel renders an attestation mode for an error message, naming the
// unattested zero value rather than printing an empty string.
func modeLabel(m config.AttestMode) string {
	if m == config.AttestNone {
		return "none"
	}
	return string(m)
}
