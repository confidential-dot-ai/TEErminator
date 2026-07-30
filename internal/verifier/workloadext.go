package verifier

// Matched-workload stamp parser, vendored from c8s pkg/ratls: TEErminator does
// not import the c8s module, so the small .1.5 parser lives here and is kept
// honest by the golden DER vector shared with c8s and c8s-verify-js
// (workloadext_test.go). The stamp is placed by CDS in the CA-signed area of
// the mesh leaf; the mesh CA signature — never the hardware evidence — is what
// vouches for it, so it may only be read off a leaf whose chain to the
// committed CA has already been verified.

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
)

// oidMatchedWorkload identifies the matched-workload extension:
//
//	1.3.6.1.4.1.59888.1.5 - matched workload extension
var oidMatchedWorkload = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 5}

// matchedWorkloadVersion is the only encoding version this package parses. An
// unknown version fails closed.
const matchedWorkloadVersion = 1

// allowlistDigestSize is the exact length of the canonical-allowlist SHA-256.
const allowlistDigestSize = 32

// MaxWorkloadNameLen is the longest allowed workload entry name, in bytes.
const MaxWorkloadNameLen = 63

// workloadNamePattern is the allowlist workload-name grammar.
var workloadNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// allowlistVersionPattern is the canonical positive decimal integer the store's
// monotonic version counter emits: 1–20 ASCII digits, no leading zero.
var allowlistVersionPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// ValidWorkloadName reports whether s is a valid workload entry name
// (1..MaxWorkloadNameLen bytes, [A-Za-z0-9][A-Za-z0-9._-]*).
func ValidWorkloadName(s string) bool {
	return len(s) <= MaxWorkloadNameLen && workloadNamePattern.MatchString(s)
}

// MatchedWorkload names the allowlist entry a leaf's attested container set
// uniquely matched at issuance, and the exact policy snapshot the match was
// decided under.
type MatchedWorkload struct {
	// Name is the matched entry name (workload-name grammar).
	Name string
	// AllowlistVersion is the store's monotonic version counter at the
	// snapshot the match used — a canonical positive decimal integer.
	AllowlistVersion string
	// AllowlistDigest is SHA-256 of the canonical allowlist bytes of that
	// snapshot, exactly 32 bytes.
	AllowlistDigest []byte
}

// matchedWorkloadASN1 is the DER encoding:
//
//	MatchedWorkload ::= SEQUENCE {
//	    formatVersion    INTEGER,           -- exactly 1
//	    name             IA5String,         -- 1..63 bytes, workload-name grammar
//	    allowlistVersion IA5String,         -- 1..20 decimal digits, no leading zero
//	    allowlistDigest  OCTET STRING (32)  -- SHA-256(canonical allowlist bytes)
//	}
type matchedWorkloadASN1 struct {
	FormatVersion    int
	Name             string `asn1:"ia5"`
	AllowlistVersion string `asn1:"ia5"`
	AllowlistDigest  []byte
}

// validate rejects a value this parser must not accept.
func (m *MatchedWorkload) validate() error {
	if !ValidWorkloadName(m.Name) {
		return fmt.Errorf("matched-workload name %q is not a valid workload entry name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", m.Name, MaxWorkloadNameLen)
	}
	if !allowlistVersionPattern.MatchString(m.AllowlistVersion) {
		return fmt.Errorf("matched-workload allowlist version %q is not a canonical positive decimal integer", m.AllowlistVersion)
	}
	if len(m.AllowlistDigest) != allowlistDigestSize {
		return fmt.Errorf("matched-workload allowlist digest must be %d bytes, got %d", allowlistDigestSize, len(m.AllowlistDigest))
	}
	return nil
}

// unmarshalMatchedWorkload decodes a DER-encoded matched-workload extension
// value, requiring the one canonical encoding: minimal DER, no trailing bytes
// or fields, byte-exact against re-encoding — no two distinct extension values
// may parse to the same MatchedWorkload.
func unmarshalMatchedWorkload(der []byte) (*MatchedWorkload, error) {
	var raw matchedWorkloadASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal matched workload: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d trailing bytes after matched-workload extension", len(rest))
	}
	if raw.FormatVersion != matchedWorkloadVersion {
		return nil, fmt.Errorf("unsupported matched-workload version %d (supported: %d)", raw.FormatVersion, matchedWorkloadVersion)
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode matched workload: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("matched-workload extension is not the exact v%d encoding (%d bytes, canonical is %d)", matchedWorkloadVersion, len(der), len(reencoded))
	}
	m := &MatchedWorkload{
		Name:             raw.Name,
		AllowlistVersion: raw.AllowlistVersion,
		AllowlistDigest:  raw.AllowlistDigest,
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// matchedWorkloadFromCert returns the certificate's matched-workload stamp, or
// nil when the certificate carries none. A present but malformed or duplicated
// extension is an error, never nil — a verifier must not read damage as
// absence.
func matchedWorkloadFromCert(cert *x509.Certificate) (*MatchedWorkload, error) {
	var found *MatchedWorkload
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidMatchedWorkload) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("certificate carries more than one matched-workload extension")
		}
		m, err := unmarshalMatchedWorkload(ext.Value)
		if err != nil {
			return nil, err
		}
		found = m
	}
	return found, nil
}
