package verifier

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// RegisterSize is the byte length of a TDX measurement register (SHA-384).
const RegisterSize = runtimemeasure.Size

// ImagePins is the complete TDX measurement identity of one guest image:
// MRTD (the TDVF firmware's measured regions) plus RTMR[1] (guest kernel /
// UKI image identity) and RTMR[2] (guest rootfs / UKI section chain). MRTD
// alone does not identify an image — two different guest images built against
// the same firmware share it — so the three registers are only meaningful as
// one tuple from one build.
type ImagePins struct {
	MRTD  [RegisterSize]byte
	RTMR1 [RegisterSize]byte
	RTMR2 [RegisterSize]byte
}

// LoadImageManifest loads a TDX image pin — the MRTD + RTMR[1] + RTMR[2]
// tuple — atomically from one build-artifact manifest. It uses the
// attestation-go loader c8s verify uses, so both accept the same files: a
// confos build manifest nesting the tuple under "tdx", or a flat object with
// "mrtd", "rtmr1" and "rtmr2". A missing, repeated or malformed register
// fails the whole load.
func LoadImageManifest(path string) (ImagePins, error) {
	id, err := runtimemeasure.LoadImageManifestFor(path, teetypes.FamilyTDX)
	if err != nil {
		return ImagePins{}, err
	}
	launch, rtmrs := id.LaunchDigests(), id.RTMRs()
	if len(launch) != 1 || len(rtmrs) != 2 {
		return ImagePins{}, fmt.Errorf("image manifest %s: TDX pin has %d launch digests and %d RTMRs, want 1 and 2", path, len(launch), len(rtmrs))
	}
	return ImagePins{MRTD: launch[0].Digest, RTMR1: rtmrs[1], RTMR2: rtmrs[2]}, nil
}

// ParseRegisterHex parses one measurement-register value under the manifest
// rule: exactly 96 lowercase hex chars. It reads the --expected-rtmr3 pin.
func ParseRegisterHex(s string) ([RegisterSize]byte, error) {
	b, err := teetypes.ParseDigest(s, RegisterSize)
	if err != nil {
		return [RegisterSize]byte{}, err
	}
	return [RegisterSize]byte(b), nil
}
