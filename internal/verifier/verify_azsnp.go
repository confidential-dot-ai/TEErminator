package verifier

import "github.com/confidential-dot-ai/attestation-go/attestation/azsnp"

// az-snp attestation verification lives in the shared attestation-go library
// (the Go sibling of attestation-rs), so TEErminator and other consumers verify
// the same evidence the same way. This file is the thin TEErminator-local façade
// over it; freshness/measurement *policy* stays in flow.go.

// AzSnpResult aliases the shared verifier's result type.
type AzSnpResult = azsnp.Result

// VerifyAzSnp verifies an az-snp Attestation-Report payload (SNP report
// signature + VCEK chain, plus HCL var_data and vTPM quote decoding) via
// attestation-go.
func VerifyAzSnp(raw []byte) (*azsnp.Result, error) {
	return azsnp.Verify(raw)
}

// VerifyAzSnpAttestation reports only whether the az-snp hardware report is
// valid, discarding the parsed result.
func VerifyAzSnpAttestation(raw []byte) error {
	return azsnp.VerifyAttestation(raw)
}
