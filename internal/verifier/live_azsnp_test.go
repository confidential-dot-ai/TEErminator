package verifier

import (
	"encoding/hex"
	"os"
	"testing"
)

// TestLiveAzSnp verifies a real az-snp attestation envelope captured from an
// Azure SEV-SNP Confidential VM. It is skipped unless TEERMINATOR_EVIDENCE
// points at a JSON file in the az-snp envelope shape
// ({"platform":"az-snp","evidence":{"hcl_report":...,"vcek":...}}).
//
// Run with:
//
//	TEERMINATOR_EVIDENCE=/path/to/az-snp-evidence.json \
//	  go test ./internal/verifier -run TestLiveAzSnp -v
//
// This drives TEErminator's production SEV-SNP verification core
// (VerifyAzSnp -> go-sev-guest verify.SnpAttestation) against the same evidence
// the attestation-rs and c8s-verify-js verifiers consume, so all three can be
// compared on one hardware report.
func TestLiveAzSnp(t *testing.T) {
	path := os.Getenv("TEERMINATOR_EVIDENCE")
	if path == "" {
		t.Skip("set TEERMINATOR_EVIDENCE to a captured az-snp evidence JSON file")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading evidence %q: %v", path, err)
	}

	res, err := VerifyAzSnp(raw)
	if err != nil {
		t.Fatalf("VerifyAzSnp failed: %v", err)
	}

	t.Logf("TEErminator verified az-snp report")
	t.Logf("  launch measurement : %s", res.Measurement)
	t.Logf("  report_data        : %s", hex.EncodeToString(res.ReportData))
}
