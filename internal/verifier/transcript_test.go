package verifier

// Golden-vector tests for the reimplemented c8s wire formats. The expected
// values were computed ONCE against the reference implementation
// (c8s pkg/ratls ReportDataForKeyAndClaims, branch feat/cds-rollup) with the
// same fixed inputs; only the resulting constants are committed. If any part
// of the transcript drifts — domain separator, frame width, endianness, field
// order, SPKI encoding — these fail, instead of every live derive failing
// closed with no CI signal.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	// goldenClaimsDERHex is asn1.Marshal of a v3 claims struct with digests
	// 0x11…, 0x22…, 0x33…, 0x44…, 0x55… (32 bytes each).
	goldenClaimsDERHex = "3081ad0201030420111111111111111111111111111111111111111111111111111111111111111104202222222222222222222222222222222222222222222222222222222222222222042033333333333333333333333333333333333333333333333333333333333333330420444444444444444444444444444444444444444444444444444444444444444404205555555555555555555555555555555555555555555555555555555555555555"

	// goldenECDSASPKIHex is the PKIX SubjectPublicKeyInfo DER of the fixed
	// ECDSA P-256 public key the ECDSA vector was generated with.
	goldenECDSASPKIHex = "3059301306072a8648ce3d020106082a8648ce3d03010703420004bebb03c68ec6e40f46b0b636455891de4a4b17dc933eaa739dc0a97b74ac3206a7c25a97db9cd767f2530fdf6e554ddb40471157a804ac927ea7d2a848fb22cb"

	// Reference outputs of ratls.ReportDataForKeyAndClaims(pub, claims, nil):
	// 64 bytes, SHA-384 in the first 48, zero-padded.
	goldenECDSAReportDataHex   = "a6f86f281620e5f3a785b9759927d6286fd6eee34fd8b5ef0e428305b7c03439b34175644cdbcffd42cb84b64d06b0a100000000000000000000000000000000"
	goldenEd25519ReportDataHex = "7253a038d03d1e6fdd5f60fb70e38061abd305ab5591408a20aed6c6c9b1f4603d9499c5424c49c417d3a05b66c37a5900000000000000000000000000000000"
)

// goldenECDSAPub parses the committed SPKI. Parsing then re-marshalling a
// standard P-256 SPKI is byte-stable, so the transcript hashes exactly these
// bytes — the same path AttestCDSIdentity takes with cert.PublicKey.
func goldenECDSAPub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(mustHex(t, goldenECDSASPKIHex))
	if err != nil {
		t.Fatalf("parse golden SPKI: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("golden SPKI is %T, want *ecdsa.PublicKey", pub)
	}
	return ec
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant: %v", err)
	}
	return b
}

func rep32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// The committed claims constant must be exactly what encoding/asn1 produces
// for the v3 struct — pinning the claims encoding itself, not just the hash.
func TestGoldenClaimsDERMatchesEncoding(t *testing.T) {
	got, err := asn1.Marshal(claimsV3{
		Version:            3,
		OperatorKeysDigest: rep32(0x11),
		SeedDigest:         rep32(0x22),
		WorkloadDigest:     rep32(0x33),
		MeshCADigest:       rep32(0x44),
		AllowlistDigest:    rep32(0x55),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if hex.EncodeToString(got) != goldenClaimsDERHex {
		t.Fatalf("claims encoding drifted:\n got  %x\n want %s", got, goldenClaimsDERHex)
	}
}

func TestReportDataGoldenVectorECDSA(t *testing.T) {
	want := mustHex(t, goldenECDSAReportDataHex)

	got, err := reportDataForKeyAndClaims(goldenECDSAPub(t), mustHex(t, goldenClaimsDERHex))
	if err != nil {
		t.Fatalf("reportDataForKeyAndClaims: %v", err)
	}
	// The reference returns [64]byte with the SHA-384 zero-padded; ours
	// returns the 48-byte digest and lets attestation-go pad. Equivalence is:
	// digest matches the first 48 bytes, and the reference's tail is zero.
	if !bytes.Equal(got, want[:48]) {
		t.Fatalf("transcript diverged from the c8s reference:\n got  %x\n want %x", got, want[:48])
	}
	if !bytes.Equal(want[48:], make([]byte, 16)) {
		t.Fatal("golden vector tail is not zero padding; the constant is corrupt")
	}
}

func TestReportDataGoldenVectorEd25519(t *testing.T) {
	want := mustHex(t, goldenEd25519ReportDataHex)
	pub := ed25519.PublicKey(rep32(0xA5))

	got, err := reportDataForKeyAndClaims(pub, mustHex(t, goldenClaimsDERHex))
	if err != nil {
		t.Fatalf("reportDataForKeyAndClaims: %v", err)
	}
	if !bytes.Equal(got, want[:48]) {
		t.Fatalf("ed25519 transcript diverged from the c8s reference:\n got  %x\n want %x", got, want[:48])
	}
}

// The golden claims must parse, and the parsed digests must be the inputs —
// exercising the v3 path of parseConfigClaims offline.
func TestParseConfigClaimsGoldenV3(t *testing.T) {
	claims, err := parseConfigClaims(mustHex(t, goldenClaimsDERHex))
	if err != nil {
		t.Fatalf("parseConfigClaims: %v", err)
	}
	for name, pair := range map[string][2][]byte{
		"operator-keys": {claims.OperatorKeysDigest, rep32(0x11)},
		"seed":          {claims.SeedDigest, rep32(0x22)},
		"workload":      {claims.WorkloadDigest, rep32(0x33)},
		"mesh-ca":       {claims.MeshCADigest, rep32(0x44)},
		"allowlist":     {claims.AllowlistDigest, rep32(0x55)},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Errorf("%s digest = %x, want %x", name, pair[0], pair[1])
		}
	}
}

// Canonicality: a SEQUENCE with an extra trailing element parses into the v3
// struct under encoding/asn1's tolerance, but must be rejected by the
// byte-exact round-trip — otherwise two distinct extension values could yield
// one parsed claims value while REPORTDATA binds the raw bytes.
func TestParseConfigClaimsRejectsNonCanonical(t *testing.T) {
	type v3Extra struct {
		Version            int
		OperatorKeysDigest []byte
		SeedDigest         []byte
		WorkloadDigest     []byte
		MeshCADigest       []byte
		AllowlistDigest    []byte
		Extra              int
	}
	der, err := asn1.Marshal(v3Extra{3, rep32(0x11), rep32(0x22), rep32(0x33), rep32(0x44), rep32(0x55), 7})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = parseConfigClaims(der)
	if err == nil {
		t.Fatal("claims with an extra SEQUENCE element were accepted")
	}
	if !strings.Contains(err.Error(), "exact v3 encoding") {
		t.Errorf("error = %q, want a canonical-encoding rejection", err)
	}
}

func TestParseConfigClaimsRejectsTrailingBytes(t *testing.T) {
	der := append(mustHex(t, goldenClaimsDERHex), 0x00)
	if _, err := parseConfigClaims(der); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error = %v, want a trailing-bytes rejection", err)
	}
}

func TestParseConfigClaimsRejectsShortDigest(t *testing.T) {
	der, err := asn1.Marshal(claimsV3{3, rep32(0x11), rep32(0x22), rep32(0x33), bytes.Repeat([]byte{0x44}, 16), rep32(0x55)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseConfigClaims(der); err == nil || !strings.Contains(err.Error(), "16 bytes, want 32") {
		t.Errorf("error = %v, want a digest-width rejection", err)
	}
}

func TestParseConfigClaimsRejectsUnknownVersion(t *testing.T) {
	der, err := asn1.Marshal(claimsV3{4, rep32(0x11), rep32(0x22), rep32(0x33), rep32(0x44), rep32(0x55)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseConfigClaims(der); err == nil || !strings.Contains(err.Error(), "unsupported config-claims version 4") {
		t.Errorf("error = %v, want an unsupported-version rejection", err)
	}
}
