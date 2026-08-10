package verifier

import (
	"bytes"
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
// parser (TEErminator must not import the c8s module). Nothing mechanically
// links the two: what keeps them from drifting is that this file and the
// reject table in imagemanifest_test.go are maintained as verbatim copies of
// their c8s counterparts, so a divergence shows up as a diff.
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
// must be a JSON object carrying all three fields ("mrtd", "rtmr1", "rtmr2")
// exactly once each, every one exactly 96 lowercase hex chars; a missing,
// repeated or malformed field fails the whole load, so a policy can never end
// up pinning part of an image, or a value other than the one it reads as. A
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
	if err := rejectDuplicateRegisters(data); err != nil {
		return ImagePins{}, fmt.Errorf("image manifest %s: %w", path, err)
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

// rejectDuplicateRegisters fails a manifest that names any of the three
// register keys more than once. encoding/json silently keeps the LAST
// occurrence, so {"mrtd":"<published>","mrtd":"<attacker>"} loads as one value
// while a human (and any diff or signature-over-the-published-line review)
// reads the other. Unknown extra fields stay tolerated — build manifests carry
// plenty — but the three registers this pin is made of must be unambiguous.
func rejectDuplicateRegisters(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil // not a JSON object; Unmarshal already reported the shape
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil
	}
	seen := make(map[string]bool, 3)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil
		}
		// Decode consumes the whole value, nested objects and arrays included,
		// so the loop only ever sees top-level keys.
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil
		}
		switch key {
		case "mrtd", "rtmr1", "rtmr2":
			if seen[key] {
				return fmt.Errorf("duplicate %q key — a register may be named only once, since JSON parsing would silently keep the last value", key)
			}
			seen[key] = true
		}
	}
	return nil
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
