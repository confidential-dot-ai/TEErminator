package verifier

import (
	"encoding/base64"
	"fmt"

	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/confidential-dot-ai/attestation-go/attestation"
)

// VerifyAttestation verifies a base64-encoded binarypb attestation carried in
// TLS headers from a remote. It returns the verified machine state on success.
func VerifyAttestation(encodedAttestation string, nonce []byte, teeNonce []byte) (*pb.MachineState, error) {
	attestationBytes, err := base64.StdEncoding.DecodeString(encodedAttestation)
	if err != nil {
		return nil, fmt.Errorf("decoding attestation: %w", err)
	}

	machineState, err := attestation.VerifyAttestation(attestationBytes, "binarypb", nonce, teeNonce)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}

	return machineState, nil
}
