package verifier

import (
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// ErrNotImplemented is returned by flows that are defined but not yet wired up.
var ErrNotImplemented = errors.New("attestation flow not implemented")

// Input carries everything a flow needs to make a verdict for one verification.
type Input struct {
	Remote *config.Remote
	// Nonce is the challenge the client sent on the request (Flow A).
	Nonce []byte
	// ResponseHeader is the remote's response header (Flow A).
	ResponseHeader http.Header
	// PeerCertificates is the verified TLS chain from the live connection.
	PeerCertificates []*x509.Certificate
}

// Result is the outcome of a verification.
type Result struct {
	Measurement string
}

// Verifier produces a verdict for a remote. Implementations are selected by the
// remote's AttestMode.
type Verifier interface {
	Verify(in Input) (*Result, error)
}

// For returns the Verifier for a remote's mode. AttestNone yields a nil
// Verifier (caller skips verification).
func For(mode config.AttestMode) (Verifier, error) {
	switch mode {
	case config.AttestNone:
		return nil, nil
	case config.AttestTLSHeader:
		return tlsHeaderVerifier{}, nil
	case config.AttestEndpoint:
		// Flow B is not a passive response verifier: it actively fetches a fresh
		// attestation bundle at session start. The proxy builds it via
		// NewEndpointAttester, so For is never called for this mode.
		return nil, fmt.Errorf("attestation mode %q is served by the endpoint attester, not For", mode)
	case config.AttestCDSCert:
		return notImplemented{"cds-cert"}, nil
	default:
		return nil, fmt.Errorf("unknown attestation mode %q", mode)
	}
}

// AttestationHeader is the response header carrying the remote's evidence.
const AttestationHeader = "Attestation-Report"

// NonceHeader carries the client's freshness nonce on the request and is echoed
// on the response.
const NonceHeader = "X-Attestation-Nonce"

// CertFingerprintHeader optionally carries the SHA-256 of the cert the evidence
// is bound to, so the client can confirm it matches the TLS peer cert.
const CertFingerprintHeader = "X-Attestation-Cert-SHA256"

// tlsHeaderVerifier implements Flow A: verify the SNP evidence in the response
// header, enforce the measurement allowlist, and bind the verdict to the client
// nonce so a replayed report from a previous session is rejected.
//
// Two nonce bindings are accepted, covering both SNP attestation shapes:
//   - Direct (bare-metal SEV-SNP): the hardware report_data carries the nonce,
//     checked by reportDataBindsNonce.
//   - vTPM (Azure az-snp CVM): the hardware report_data binds the vTPM AK, and
//     the nonce rides in an AK-signed TPM quote (evidence.tpm_quote). The
//     report_data->AK->quote->nonce chain is checked by the shared
//     attestation-go verifier (azsnp.Result.VerifyVTPMFreshness).
type tlsHeaderVerifier struct{}

func (tlsHeaderVerifier) Verify(in Input) (*Result, error) {
	if in.ResponseHeader == nil {
		return nil, fmt.Errorf("flow A: no response header to verify")
	}
	raw := in.ResponseHeader.Get(AttestationHeader)
	if raw == "" {
		return nil, fmt.Errorf("flow A: response is missing the %s header", AttestationHeader)
	}

	res, err := VerifyAzSnp([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("flow A: %w", err)
	}

	if err := checkMeasurement(res.Measurement, in.Remote.Measurements); err != nil {
		return nil, err
	}

	// Freshness: the client nonce must be bound into the evidence. Accept either
	// SNP attestation shape so one tls-header remote can be backed by bare-metal
	// SNP or an Azure CVM.
	if len(in.Nonce) > 0 {
		switch {
		case reportDataBindsNonce(res.ReportData, in.Nonce):
			// Direct binding (bare-metal SEV-SNP): the hardware report_data
			// carries the nonce (raw prefix or SHA-384 digest).
		case res.TPMQuote != nil:
			// vTPM binding (Azure az-snp): the nonce lives in the AK-signed TPM
			// quote because the hardware report_data binds the AK, not the nonce.
			if err := res.VerifyVTPMFreshness(in.Nonce); err != nil {
				return nil, fmt.Errorf("flow A (az-snp vTPM): %w", err)
			}
		default:
			return nil, fmt.Errorf("flow A: report_data does not bind the request nonce and no vTPM quote is present (stale or replayed evidence)")
		}
	}

	return &Result{Measurement: res.Measurement}, nil
}

func reportDataBindsNonce(reportData, nonce []byte) bool {
	if len(reportData) == 0 {
		return false
	}
	if len(nonce) <= len(reportData) &&
		subtle.ConstantTimeCompare(reportData[:len(nonce)], nonce) == 1 {
		return true
	}
	digest := sha512.Sum384(nonce)
	if len(digest) <= len(reportData) &&
		subtle.ConstantTimeCompare(reportData[:len(digest)], digest[:]) == 1 {
		return true
	}
	return false
}

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
	return fmt.Errorf("flow A: launch measurement %s is not in the allowlist", measurement)
}

type notImplemented struct{ mode string }

func (n notImplemented) Verify(Input) (*Result, error) {
	return nil, fmt.Errorf("%w: %s (use the c8s-verify-js browser client for this flow today)", ErrNotImplemented, n.mode)
}
