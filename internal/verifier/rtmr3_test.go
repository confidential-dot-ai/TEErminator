package verifier

import (
	"encoding/hex"
	"strings"
	"testing"
)

const validRTMR3 = "a9b91d920971de864899fb5925c4b5230bf88750dd59866d8d34aeb975e86761ea7488ade961908d9595b6202c9e6470"

func TestParseRTMR3(t *testing.T) {
	got, err := parseRTMR3(validRTMR3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(got) != validRTMR3 {
		t.Errorf("round-trip = %x, want %s", got, validRTMR3)
	}
	if len(got) != rtmr3Len {
		t.Errorf("len = %d, want %d", len(got), rtmr3Len)
	}
}

func TestParseRTMR3AcceptsSurroundingWhitespace(t *testing.T) {
	// Pins get copy-pasted out of terminal output and config files.
	if _, err := parseRTMR3("  " + validRTMR3 + "\n"); err != nil {
		t.Errorf("whitespace-padded pin rejected: %v", err)
	}
}

// A malformed pin must be an error, never a silently skipped check — that
// would leave a remote looking pinned while verifying nothing.
func TestParseRTMR3Rejects(t *testing.T) {
	for _, tc := range []struct{ name, in, wantErr string }{
		{"empty", "", "want 48"},
		{"not hex", strings.Repeat("zz", 48), "not hex"},
		{"too short", "deadbeef", "want 48"},
		{"too long", strings.Repeat("ab", 64), "want 48"},
		{"odd length", validRTMR3[:len(validRTMR3)-1], "not hex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRTMR3(tc.in)
			if err == nil {
				t.Fatalf("expected an error, got %x", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// The register is TDX-only. attestation-go consults RTMR pins only on the TDX
// path, so accepting one for another platform would drop it silently.
func TestVerifyEndpointEvidenceRejectsRTMR3PinOnNonTDX(t *testing.T) {
	for _, platform := range []string{"snp", "az-snp", "az-tdx", "gcp-snp"} {
		t.Run(platform, func(t *testing.T) {
			b := attestationBundle{Platform: platform, Evidence: []byte(`{}`)}
			_, err := verifyEndpointEvidence(b, make([]byte, 48), validRTMR3)
			if err == nil {
				t.Fatal("expected a rejection, got none")
			}
			if !strings.Contains(err.Error(), "TDX-only") {
				t.Errorf("error = %q, want it to explain the pin cannot be enforced", err)
			}
		})
	}
}

// A malformed pin must be caught before any network verification, so the
// operator sees the config error rather than a downstream attestation failure.
func TestVerifyEndpointEvidenceRejectsMalformedPinEarly(t *testing.T) {
	b := attestationBundle{Platform: "tdx", Evidence: []byte(`{}`)}
	_, err := verifyEndpointEvidence(b, make([]byte, 48), "not-a-pin")
	if err == nil || !strings.Contains(err.Error(), "not hex") {
		t.Errorf("error = %v, want a hex parse failure", err)
	}
}
