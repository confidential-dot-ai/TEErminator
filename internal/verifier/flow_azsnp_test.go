package verifier

import (
	_ "embed"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

//go:embed testdata/attestation.json
var azSnpFixture []byte

// TestTLSHeaderVerifier_AzSnpDispatch drives the Flow A verifier with a real
// az-snp response header and checks the two-flow nonce dispatch end to end:
//   - no nonce required: the hardware report verifies and the measurement is
//     returned;
//   - a fresh nonce required: recorded evidence (empty vTPM qualifyingData)
//     cannot satisfy either binding, so it fails closed rather than forwarding
//     stale evidence.
func TestTLSHeaderVerifier_AzSnpDispatch(t *testing.T) {
	hdr := http.Header{}
	hdr.Set(AttestationHeader, string(azSnpFixture))

	remote := &config.Remote{Mode: config.AttestTLSHeader}
	vf := tlsHeaderVerifier{}

	// No nonce: verification succeeds and surfaces the launch measurement.
	res, err := vf.Verify(Input{Remote: remote, ResponseHeader: hdr})
	if err != nil {
		t.Fatalf("expected az-snp evidence to verify without a nonce: %v", err)
	}
	if res.Measurement == "" {
		t.Fatal("expected a launch measurement")
	}

	// Fresh nonce: recorded evidence is not bound to it, via neither report_data
	// nor the vTPM quote, so the verifier must fail closed.
	_, err = vf.Verify(Input{Remote: remote, Nonce: make([]byte, 32), ResponseHeader: hdr})
	if err == nil {
		t.Fatal("expected stale recorded evidence to be rejected for a fresh nonce")
	}
}
