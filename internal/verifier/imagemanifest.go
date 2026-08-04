package verifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// RegisterSize is the byte length of a TDX measurement register (SHA-384).
const RegisterSize = 48

// ImagePins is the complete TDX measurement identity of one guest image:
// MRTD (the TDVF firmware's measured regions) plus RTMR[1] (guest kernel /
// UKI image identity) and RTMR[2] (guest rootfs / UKI section chain). MRTD
// alone does not identify an image — two different guest images built against
// the same firmware share it — so the three registers are only meaningful as
// one tuple from one build.
//
// This is a vendored mirror of the c8s pkg/runtimemeasure image-manifest
// parser (TEErminator must not import the c8s module); the shared
// testdata/image_manifest.json fixture keeps the two implementations honest.
type ImagePins struct {
	MRTD  [RegisterSize]byte
	RTMR1 [RegisterSize]byte
	RTMR2 [RegisterSize]byte
}

// imageManifest is the JSON subset LoadImageManifest reads. Extra fields are
// allowed (build manifests carry other data); the three registers are not
// optional.
type imageManifest struct {
	MRTD  string `json:"mrtd"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// LoadImageManifest loads a TDX image pin — the MRTD + RTMR[1] + RTMR[2]
// tuple — atomically from one provenanced build-artifact manifest. The file
// must be a JSON object carrying all three fields ("mrtd", "rtmr1", "rtmr2"),
// each exactly 96 lowercase hex chars; a missing or malformed field fails the
// whole load, so a policy can never end up pinning part of an image. A
// generic artifact-hash manifest.json (file digests of build outputs) is not
// an image pin and is rejected by the same rule.
func LoadImageManifest(path string) (ImagePins, error) {
	var pins ImagePins
	data, err := os.ReadFile(path)
	if err != nil {
		return pins, fmt.Errorf("read image manifest: %w", err)
	}
	var m imageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return pins, fmt.Errorf("image manifest %s is not a JSON object: %w", path, err)
	}
	for _, f := range []struct {
		name string
		hex  string
		dst  *[RegisterSize]byte
	}{
		{"mrtd", m.MRTD, &pins.MRTD},
		{"rtmr1", m.RTMR1, &pins.RTMR1},
		{"rtmr2", m.RTMR2, &pins.RTMR2},
	} {
		if f.hex == "" {
			return ImagePins{}, fmt.Errorf(
				"image manifest %s: missing %q — a TDX image pin is the mrtd+rtmr1+rtmr2 tuple from one provenanced build-artifact manifest; a generic artifact-hash manifest.json is not it",
				path, f.name)
		}
		if err := decodeRegister(f.hex, f.dst); err != nil {
			return ImagePins{}, fmt.Errorf("image manifest %s: %q %w", path, f.name, err)
		}
	}
	return pins, nil
}

// ParseRegisterHex parses a single measurement-register value under the same
// rule as the manifest fields: exactly 96 lowercase hex chars. Used for the
// --expected-rtmr3 pin.
func ParseRegisterHex(s string) ([RegisterSize]byte, error) {
	var out [RegisterSize]byte
	if err := decodeRegister(s, &out); err != nil {
		return [RegisterSize]byte{}, err
	}
	return out, nil
}

// decodeRegister parses exactly 96 lowercase hex chars into a register value.
// Uppercase is rejected rather than folded: the manifest is a measurement
// reference, and accepting mixed case would let two spellings of one value
// slip past byte-exact comparisons elsewhere.
func decodeRegister(s string, dst *[RegisterSize]byte) error {
	if len(s) != RegisterSize*2 {
		return fmt.Errorf("is %d chars, want %d lowercase hex chars", len(s), RegisterSize*2)
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("is not %d lowercase hex chars", RegisterSize*2)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("is not hex: %w", err)
	}
	copy(dst[:], b)
	return nil
}
