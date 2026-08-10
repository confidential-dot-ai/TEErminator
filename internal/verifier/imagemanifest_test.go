package verifier

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	mrtdHex  = strings.Repeat("1a", RegisterSize)
	rtmr1Hex = strings.Repeat("2b", RegisterSize)
	rtmr2Hex = strings.Repeat("3c", RegisterSize)
)

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadImageManifestValid(t *testing.T) {
	// Extra unknown fields are allowed: build manifests carry other data, and
	// only the three register keys must be unambiguous — a repeated unknown
	// key (and a nested object naming "mrtd") is none of this loader's
	// business.
	p := writeManifest(t, `{
		"schema": 3, "schema": 4,
		"artifacts": {"kernel": "deadbeef", "mrtd": "ignored", "mrtd": "ignored"},
		"mrtd": "`+mrtdHex+`",
		"rtmr1": "`+rtmr1Hex+`",
		"rtmr2": "`+rtmr2Hex+`"
	}`)
	pins, err := LoadImageManifest(p)
	if err != nil {
		t.Fatalf("LoadImageManifest: %v", err)
	}
	for _, reg := range []struct {
		name string
		got  [RegisterSize]byte
		want string
	}{
		{"mrtd", pins.MRTD, mrtdHex},
		{"rtmr1", pins.RTMR1, rtmr1Hex},
		{"rtmr2", pins.RTMR2, rtmr2Hex},
	} {
		if hex.EncodeToString(reg.got[:]) != reg.want {
			t.Errorf("%s = %x, want %s", reg.name, reg.got, reg.want)
		}
	}
}

// TestLoadImageManifestFixture loads the checked-in fixture, which exercises
// the accepted format end to end. c8s holds no copy of this file, so it proves
// nothing about the c8s parser on its own: what keeps the two aligned is that
// this file's reject table below is maintained as a verbatim copy of the c8s
// pkg/runtimemeasure one, so a divergence shows up as a diff.
func TestLoadImageManifestFixture(t *testing.T) {
	pins, err := LoadImageManifest(filepath.Join("testdata", "image_manifest.json"))
	if err != nil {
		t.Fatalf("LoadImageManifest: %v", err)
	}
	if hex.EncodeToString(pins.MRTD[:]) != strings.Repeat("aa", RegisterSize) {
		t.Errorf("fixture mrtd = %x", pins.MRTD)
	}
	if hex.EncodeToString(pins.RTMR1[:]) != strings.Repeat("bb", RegisterSize) {
		t.Errorf("fixture rtmr1 = %x", pins.RTMR1)
	}
	if hex.EncodeToString(pins.RTMR2[:]) != strings.Repeat("cc", RegisterSize) {
		t.Errorf("fixture rtmr2 = %x", pins.RTMR2)
	}
}

func TestLoadImageManifestRejects(t *testing.T) {
	for _, tc := range []struct{ name, content, wantErr string }{
		{"not json", "not json at all", "not a JSON object"},
		{"json array", `[1,2,3]`, "not a JSON object"},
		{"missing mrtd",
			`{"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "mrtd"`},
		{"missing rtmr1",
			`{"mrtd":"` + mrtdHex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "rtmr1"`},
		{"missing rtmr2",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `"}`,
			`missing "rtmr2"`},
		{"generic artifact-hash manifest",
			`{"files":{"disk.img":"sha256:abc"}}`,
			"a generic artifact-hash manifest.json is not it"},
		{"bad hex",
			`{"mrtd":"` + strings.Repeat("zz", RegisterSize) + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"uppercase hex",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + strings.ToUpper(rtmr1Hex) + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"wrong length",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"aabb"}`,
			"want 96"},
		{"wrong json type", `{"mrtd":7,"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"not a JSON object"},
		// encoding/json keeps the LAST value for a repeated key, so a
		// duplicate lets the manifest load as a value other than the one it
		// reads as. Each register must be named exactly once.
		{"duplicate mrtd",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `","mrtd":"` + strings.Repeat("ff", RegisterSize) + `"}`,
			`duplicate "mrtd"`},
		{"duplicate rtmr1",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`duplicate "rtmr1"`},
		{"duplicate rtmr2",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`duplicate "rtmr2"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadImageManifest(writeManifest(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// One malformed field must fail the whole load: a partial pin (say MRTD
// without RTMR[2]) would silently verify only part of the image.
func TestLoadImageManifestIsAtomic(t *testing.T) {
	p := writeManifest(t, `{"mrtd":"`+mrtdHex+`","rtmr1":"`+rtmr1Hex+`","rtmr2":"bad"}`)
	pins, err := LoadImageManifest(p)
	if err == nil {
		t.Fatal("want error")
	}
	if pins != (ImagePins{}) {
		t.Error("a failed load must not return partial pins")
	}
}

func TestLoadImageManifestMissingFile(t *testing.T) {
	_, err := LoadImageManifest(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "read image manifest") {
		t.Errorf("error = %v, want a read error", err)
	}
}

func TestParseRegisterHex(t *testing.T) {
	got, err := ParseRegisterHex(rtmr1Hex)
	if err != nil {
		t.Fatalf("ParseRegisterHex: %v", err)
	}
	if hex.EncodeToString(got[:]) != rtmr1Hex {
		t.Errorf("register = %x, want %s", got, rtmr1Hex)
	}
	for _, bad := range []string{"", "aabb", strings.ToUpper(rtmr1Hex), strings.Repeat("zz", RegisterSize)} {
		if _, err := ParseRegisterHex(bad); err == nil {
			t.Errorf("ParseRegisterHex(%q) accepted", bad)
		}
	}
}
