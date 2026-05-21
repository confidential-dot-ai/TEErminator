package verifier

import (
	"encoding/base64"
	"testing"
)

func TestVerifyAttestation_InvalidBase64(t *testing.T) {
	_, err := VerifyAttestation("not-valid-base64!!!", []byte("nonce"), nil)
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestVerifyAttestation_InvalidProto(t *testing.T) {
	// Valid base64 but not a valid binarypb attestation proto.
	garbage := base64.StdEncoding.EncodeToString([]byte("this is not a proto"))
	_, err := VerifyAttestation(garbage, []byte("nonce"), nil)
	if err == nil {
		t.Fatal("expected error for invalid proto bytes, got nil")
	}
}
