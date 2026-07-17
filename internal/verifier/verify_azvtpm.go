package verifier

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/aztdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/azsnp"
)

// The two Azure vTPM platforms — az-snp (AMD SEV-SNP CVM) and az-tdx (Intel TDX
// CVM) — share the same evidence shape and freshness chain: the hardware report
// binds the vTPM AK, and the per-request nonce rides in an AK-signed TPM quote.
// Only the hardware layer differs (SNP report + VCEK vs. TD quote + Intel DCAP),
// which attestation-go handles behind azsnp.Verify / aztdx.Verify. This façade
// lets one tls-header/endpoint remote be backed by either platform.

// AzVTPMResult is the platform-agnostic result of Azure vTPM hardware
// verification. freshness binds a nonce through the AK-signed TPM quote.
type AzVTPMResult struct {
	// Platform is the verified platform string ("az-snp" or "az-tdx").
	Platform string
	// Measurement is the launch measurement: the SNP LAUNCH_DIGEST or the TDX
	// MRTD (both SHA-384 hex).
	Measurement string
	// ReportData is the hardware report_data (binds the vTPM AK, not the nonce).
	ReportData []byte
	// HasTPMQuote reports whether the evidence carried a vTPM quote.
	HasTPMQuote bool

	freshness func([]byte) error
}

// VerifyVTPMFreshness verifies the vTPM trust chain binds nonce:
// report_data → AK pub → AK-signed quote → quote extraData == nonce.
func (r *AzVTPMResult) VerifyVTPMFreshness(nonce []byte) error {
	if r.freshness == nil {
		return fmt.Errorf("evidence carries no vTPM quote")
	}
	return r.freshness(nonce)
}

// VerifyAzVTPM verifies an Azure vTPM Attestation-Report payload, dispatching on
// the envelope's platform to the az-snp or az-tdx hardware verifier. Freshness
// and measurement policy stay with the caller (flow.go / endpoint.go).
func VerifyAzVTPM(raw []byte) (*AzVTPMResult, error) {
	var env struct {
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parsing attestation envelope: %w", err)
	}
	switch env.Platform {
	case "az-snp":
		res, err := azsnp.Verify(raw)
		if err != nil {
			return nil, err
		}
		return &AzVTPMResult{
			Platform:    env.Platform,
			Measurement: res.Measurement,
			ReportData:  res.ReportData,
			HasTPMQuote: res.TPMQuote != nil,
			freshness:   res.VerifyVTPMFreshness,
		}, nil
	case "az-tdx":
		res, err := aztdx.Verify(raw)
		if err != nil {
			return nil, err
		}
		return &AzVTPMResult{
			Platform:    env.Platform,
			Measurement: res.Measurement,
			ReportData:  res.ReportData,
			HasTPMQuote: res.TPMQuote != nil,
			freshness:   res.VerifyVTPMFreshness,
		}, nil
	case "snp":
		return nil, fmt.Errorf("bare-metal snp is not wired for this flow; az-snp and az-tdx are supported")
	default:
		return nil, fmt.Errorf("unsupported platform %q", env.Platform)
	}
}
