package verifier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

// ErrNotImplemented is returned for attestation modes that are defined but not
// yet wired up; the proxy fails closed on them instead of forwarding.
var ErrNotImplemented = errors.New("attestation flow not implemented")

// Flow B (config.AttestEndpoint, "attest") performs the same challenge/response
// attestation as the c8s-verify-js browser client, but instead of establishing
// the post-quantum over-encryption tunnel it rides the mesh-CA-validated upstream
// TLS connection. To make that binding cryptographic rather than trust-on-first
// connection, it requests the LB's tls-cert binding (pq=false): the hardware
// report_data commits to the LB serving leaf's SPKI, which the proxy then pins
// the forwarded traffic to (see proxy.go). This is the "TLS-session scoped TEE
// binding".

// wellKnownAttestation is the LB attestation endpoint (PROTOCOL.md). It lives at
// the LB origin, independent of the remote's forwarding path.
const wellKnownAttestation = "/.well-known/c8s/attestation"

// bindingTLSCert mirrors c8s pkg/types.BindingTLSCert: the LB confirms it bound
// report_data to its serving-leaf SPKI rather than a per-session key.
const bindingTLSCert = "tls-cert"

// SessionVerdict is the outcome of a Flow B session attestation. LeafSPKI is the
// SHA-256 of the LB serving leaf's SubjectPublicKeyInfo that the attestation was
// bound to; the transport pins forwarded requests to a connection presenting the
// same leaf and re-attests otherwise.
type SessionVerdict struct {
	Measurement string
	LeafSPKI    [32]byte
}

// attestationBundle mirrors the relevant fields of the LB response
// (c8s pkg/types.AttestationBundle) for the tls-cert binding.
type attestationBundle struct {
	Version  string          `json:"version"`
	Platform string          `json:"platform"`
	Nonce    string          `json:"nonce"`
	Evidence json.RawMessage `json:"evidence"`
	Binding  string          `json:"binding"`
}

// EndpointAttester implements Flow B. baseURL is the LB origin (scheme://host);
// client must carry the same TLS trust the proxy uses for the upstream (pinned
// mesh CA + ServerName), so the leaf it observes is the one the proxy forwards
// over. pinnedRoots is that mesh-CA trust anchor, required: without it the LB's
// mesh-signed leaf cannot be validated and there is nothing to bind to.
type EndpointAttester struct {
	client      *http.Client
	attestURL   *url.URL
	remote      config.Remote
	pinnedRoots *x509.CertPool
}

// NewEndpointAttester builds a Flow B attester.
func NewEndpointAttester(baseURL string, client *http.Client, remote config.Remote, pinnedRoots *x509.CertPool) (*EndpointAttester, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("flow B: parse base URL: %w", err)
	}
	u.Path = wellKnownAttestation
	u.RawQuery = ""
	return &EndpointAttester{
		client:      client,
		attestURL:   u,
		remote:      remote,
		pinnedRoots: pinnedRoots,
	}, nil
}

// Attest runs the session-start attestation and returns the verdict, or an error
// (fail closed). The nonce binds freshness; the LB binds it together with its
// serving-leaf SPKI into the hardware evidence (pq=false).
func (e *EndpointAttester) Attest(ctx context.Context) (*SessionVerdict, error) {
	if e.pinnedRoots == nil {
		return nil, fmt.Errorf("flow B: no pinned mesh CA — add one with `teerminator certs add mesh-ca.pem` so the LB's mesh-signed leaf can be trusted")
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("flow B: generate nonce: %w", err)
	}

	u := *e.attestURL
	q := u.Query()
	q.Set("nonce", base64.RawURLEncoding.EncodeToString(nonce))
	q.Set("pq", "false") // request the tls-cert binding
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("flow B: build request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flow B: fetch attestation: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("error closing response Body", "error", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("flow B: attestation endpoint returned %d: %s", resp.StatusCode, body)
	}

	// The leaf on this (mesh-CA-validated) connection is what the LB bound and
	// what the proxy will pin forwarded traffic to.
	leafSPKI, err := leafSPKIFromTLS(resp.TLS)
	if err != nil {
		return nil, fmt.Errorf("flow B: %w", err)
	}

	var bundle attestationBundle
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("flow B: decode bundle: %w", err)
	}
	if bundle.Nonce != base64.RawURLEncoding.EncodeToString(nonce) {
		return nil, fmt.Errorf("flow B: nonce mismatch (LB echoed %q)", bundle.Nonce)
	}
	if bundle.Binding != bindingTLSCert {
		return nil, fmt.Errorf("flow B: LB did not honor pq=false (binding=%q); the cluster's tls-lb must be built with the tls-cert binding (cds-attest --serving-cert-file)", bundle.Binding)
	}

	// expected = SHA-384(serving_leaf_spki || nonce): the value the LB committed
	// to report_data, recomputed from the leaf we actually see on the wire.
	bind := make([]byte, 0, len(leafSPKI)+len(nonce))
	bind = append(bind, leafSPKI...)
	bind = append(bind, nonce...)
	expected := sha512.Sum384(bind)

	measurement, err := verifyEndpointEvidence(bundle, expected[:])
	if err != nil {
		return nil, err
	}
	if err := checkMeasurement(measurement, e.remote.Measurements); err != nil {
		return nil, err
	}

	v := &SessionVerdict{Measurement: measurement}
	v.LeafSPKI = sha256.Sum256(leafSPKI)
	return v, nil
}

// verifyEndpointEvidence verifies the hardware evidence through the shared
// attestation-go verifier (teeverify dispatches on the bundle's platform tag)
// and requires that the evidence binds expectedReportData, i.e.
// SHA-384(serving_leaf_spki || nonce): directly in the report_data for
// bare-metal platforms, or in the AK-signed vTPM quote for the Azure ones. All
// evidence parsing and cryptographic verification lives in attestation-go;
// only the binding anchor and the measurement policy are computed here.
func verifyEndpointEvidence(b attestationBundle, expectedReportData []byte) (string, error) {
	raw, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformType(b.Platform),
		Evidence: b.Evidence,
	})
	if err != nil {
		return "", fmt.Errorf("flow B: re-encode evidence: %w", err)
	}
	res, err := teeverify.Verify(raw, teetypes.VerifyParams{ExpectedReportData: expectedReportData})
	if err != nil {
		return "", fmt.Errorf("flow B (%s): %w", b.Platform, err)
	}
	return res.Claims.LaunchDigest, nil
}

// leafSPKIFromTLS returns the raw SubjectPublicKeyInfo (DER) of the peer leaf.
func leafSPKIFromTLS(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS peer certificate to bind the session to")
	}
	return state.PeerCertificates[0].RawSubjectPublicKeyInfo, nil
}

// checkMeasurement enforces the remote's launch-digest allowlist.
func checkMeasurement(measurement string, allowed []string) error {
	if len(allowed) == 0 {
		// No allowlist: the signature is verified but the workload identity is
		// not pinned. Permit, but the caller should warn.
		return nil
	}
	m := strings.ToLower(measurement)
	for i := range allowed {
		if strings.ToLower(allowed[i]) == m {
			return nil
		}
	}
	return fmt.Errorf("launch measurement %s is not in the allowlist", measurement)
}
