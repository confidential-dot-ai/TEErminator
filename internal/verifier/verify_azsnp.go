package verifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
)

// azSnpEvidence mirrors the JSON structure of testdata/attestation.json.
type azSnpEvidence struct {
	Platform string `json:"platform"`
	Evidence struct {
		HclReport string `json:"hcl_report"`
		Vcek      string `json:"vcek"`
		Version   int    `json:"version"`
	} `json:"evidence"`
}

// hclReportSNPOffset is the byte offset within an HCL report where the raw
// SEV-SNP attestation report (abi.ReportSize bytes) begins.
// The 32-byte HCL header (HCLA magic + metadata) precedes the report.
const hclReportSNPOffset = 0x20

// VerifyAzSnpAttestation reads attestation json bytes, extracts the
// SEV-SNP report embedded in the HCL report, attaches the provided VCEK
// certificate and calls verify.SnpAttestation to confirm the report is valid.
func VerifyAzSnpAttestation(raw []byte) error {
	var report azSnpEvidence
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("parsing attestation.json: %w", err)
	}

	if report.Platform != "az-snp" {
		return fmt.Errorf("unexpected platform %q, want \"az-snp\"", report.Platform)
	}

	// Decode the HCL report (base64url, no padding).
	hclBytes, err := base64.RawURLEncoding.DecodeString(report.Evidence.HclReport)
	if err != nil {
		return fmt.Errorf("decoding hcl_report: %w", err)
	}

	minLen := hclReportSNPOffset + abi.ReportSize
	if len(hclBytes) < minLen {
		return fmt.Errorf("hcl_report too short: got %d bytes, need at least %d", len(hclBytes), minLen)
	}

	snpReportBytes := hclBytes[hclReportSNPOffset : hclReportSNPOffset+abi.ReportSize]

	snpReport, err := abi.ReportToProto(snpReportBytes)
	if err != nil {
		return fmt.Errorf("parsing SNP report: %w", err)
	}

	// Decode the VCEK certificate (base64url, no padding).
	vcekDER, err := base64.RawURLEncoding.DecodeString(report.Evidence.Vcek)
	if err != nil {
		return fmt.Errorf("decoding vcek: %w", err)
	}

	attestation := &spb.Attestation{
		Report: snpReport,
		CertificateChain: &spb.CertificateChain{
			VcekCert: vcekDER,
		},
	}

	opts := sv.DefaultOptions()
	if err := sv.SnpAttestation(attestation, opts); err != nil {
		return fmt.Errorf("SnpAttestation verification failed: %w", err)
	}

	return nil
}
