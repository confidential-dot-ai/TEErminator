package verifier

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

// goldenMatchedWorkloadDER is the one canonical encoding of
// {v1, "api", "7", 0x11*32} — shared with c8s (pkg/ratls) and c8s-verify-js so
// three parsers cannot drift.
const goldenMatchedWorkloadDER = "302d0201011603617069160137" +
	"04201111111111111111111111111111111111111111111111111111111111111111"

func goldenDigest() []byte {
	return bytes.Repeat([]byte{0x11}, allowlistDigestSize)
}

func TestMatchedWorkloadGoldenVector(t *testing.T) {
	der, err := hex.DecodeString(goldenMatchedWorkloadDER)
	if err != nil {
		t.Fatal(err)
	}
	m, err := unmarshalMatchedWorkload(der)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "api" || m.AllowlistVersion != "7" || !bytes.Equal(m.AllowlistDigest, goldenDigest()) {
		t.Fatalf("golden vector parsed to %+v", m)
	}

	// The local encoder must reproduce the golden bytes exactly (re-marshal
	// equality is also what enforces minimal DER on parse).
	reencoded, err := asn1.Marshal(matchedWorkloadASN1{1, "api", "7", goldenDigest()})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(reencoded); got != goldenMatchedWorkloadDER {
		t.Fatalf("re-encoded DER = %s, want %s", got, goldenMatchedWorkloadDER)
	}
}

func TestMatchedWorkloadRejectedBoundaries(t *testing.T) {
	golden, err := hex.DecodeString(goldenMatchedWorkloadDER)
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(v matchedWorkloadASN1) []byte {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	// Non-minimal outer length (long form where short form is canonical).
	nonMinimal := append([]byte{0x30, 0x81, golden[1]}, golden[2:]...)

	for name, der := range map[string][]byte{
		"empty":                {},
		"truncated":            golden[:len(golden)-1],
		"trailing byte":        append(append([]byte(nil), golden...), 0x00),
		"unknown version 2":    marshal(matchedWorkloadASN1{2, "api", "7", goldenDigest()}),
		"version zero":         marshal(matchedWorkloadASN1{0, "api", "7", goldenDigest()}),
		"64-byte name":         marshal(matchedWorkloadASN1{1, strings.Repeat("a", 64), "7", goldenDigest()}),
		"empty name":           marshal(matchedWorkloadASN1{1, "", "7", goldenDigest()}),
		"name bad grammar":     marshal(matchedWorkloadASN1{1, ".api", "7", goldenDigest()}),
		"leading-zero version": marshal(matchedWorkloadASN1{1, "api", "07", goldenDigest()}),
		"31-byte digest":       marshal(matchedWorkloadASN1{1, "api", "7", goldenDigest()[:31]}),
		"33-byte digest":       marshal(matchedWorkloadASN1{1, "api", "7", append(goldenDigest(), 0x11)}),
		"non-minimal length":   nonMinimal,
		"not a sequence":       {0x02, 0x01, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := unmarshalMatchedWorkload(der); err == nil {
				t.Fatal("unmarshal accepted a rejected boundary")
			}
		})
	}

	// The 63-byte name boundary itself is legal.
	longest := marshal(matchedWorkloadASN1{1, strings.Repeat("a", 63), "7", goldenDigest()})
	if _, err := unmarshalMatchedWorkload(longest); err != nil {
		t.Fatalf("63-byte name rejected: %v", err)
	}
}

func TestMatchedWorkloadFromCert(t *testing.T) {
	golden, err := hex.DecodeString(goldenMatchedWorkloadDER)
	if err != nil {
		t.Fatal(err)
	}
	ext := pkix.Extension{Id: oidMatchedWorkload, Value: golden}

	t.Run("absent is nil, no error", func(t *testing.T) {
		m, err := matchedWorkloadFromCert(&x509.Certificate{})
		if err != nil || m != nil {
			t.Fatalf("m = %v, err = %v", m, err)
		}
	})
	t.Run("present parses", func(t *testing.T) {
		m, err := matchedWorkloadFromCert(&x509.Certificate{Extensions: []pkix.Extension{ext}})
		if err != nil {
			t.Fatal(err)
		}
		if m == nil || m.Name != "api" {
			t.Fatalf("m = %+v", m)
		}
	})
	t.Run("duplicate fails closed", func(t *testing.T) {
		dup := &x509.Certificate{Extensions: []pkix.Extension{ext, ext}}
		if _, err := matchedWorkloadFromCert(dup); err == nil {
			t.Fatal("duplicate extension accepted")
		}
	})
	t.Run("malformed fails closed", func(t *testing.T) {
		bad := pkix.Extension{Id: oidMatchedWorkload, Value: golden[:len(golden)-1]}
		if _, err := matchedWorkloadFromCert(&x509.Certificate{Extensions: []pkix.Extension{bad}}); err == nil {
			t.Fatal("malformed extension accepted")
		}
	})
}

func TestValidWorkloadName(t *testing.T) {
	for name, want := range map[string]bool{
		"api":                   true,
		"a":                     true,
		strings.Repeat("a", 63): true,
		"my.workload_v1-x":      true,
		"":                      false,
		strings.Repeat("a", 64): false,
		".api":                  false,
		"-api":                  false,
		"a b":                   false,
		"a/b":                   false,
	} {
		if got := ValidWorkloadName(name); got != want {
			t.Errorf("ValidWorkloadName(%q) = %v, want %v", name, got, want)
		}
	}
}
