package verifier

// The certificate validity window is, alongside the per-handshake nonce, the
// only freshness bound in the attest-lb flow: the nonce proves the evidence was
// minted for this connection, and the window is what stops a still-signed but
// retired mesh identity from backing it. Both the serving leaf and the
// committed mesh CA go through it, and the single documented notBeforeSkew is
// the only allowance — these tests exist so widening or dropping it cannot pass
// unnoticed.

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

// testCert mints a self-signed certificate with an explicit validity window.
func testCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	return mintCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "validity-fixture"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil, elliptic.P256()).cert
}

func TestCheckValidity(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
		wantErr             string
	}{
		{"valid", now.Add(-time.Hour), now.Add(time.Hour), ""},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Second), "expired"},
		{"expires exactly now is still valid", now.Add(-time.Hour), now, ""},
		{
			// The skew exists so a client whose clock trails the cluster's can
			// still use a freshly rotated identity.
			"NotBefore inside the skew is accepted",
			now.Add(notBeforeSkew - time.Second), now.Add(time.Hour), "",
		},
		{
			// One second past it is not: the allowance is a bounded clock
			// concession, not an open window on certificates that are not yet
			// meant to be in use.
			"NotBefore beyond the skew is refused",
			now.Add(notBeforeSkew + time.Second), now.Add(time.Hour), "not yet valid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkValidity(testCert(t, tc.notBefore, tc.notAfter), now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkValidity = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkValidity = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// Both certificates in the committed chain are checked, not just the leaf: an
// expired mesh CA can no longer vouch for anything it issued, however valid the
// leaf still looks.
func TestVerifyDirectChainChecksBothValidityWindows(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	chain := func(t *testing.T, caFrom, caTo, leafFrom, leafTo time.Time) (leaf, ca *x509.Certificate) {
		t.Helper()
		caPair := mintCert(t, &x509.Certificate{
			Subject:               pkix.Name{CommonName: "validity-ca"},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
			NotBefore:             caFrom,
			NotAfter:              caTo,
		}, nil, elliptic.P384())
		leafPair := mintCert(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "validity-leaf"},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			NotBefore:   leafFrom,
			NotAfter:    leafTo,
		}, caPair, elliptic.P256())
		return leafPair.cert, caPair.cert
	}

	valid := [2]time.Time{now.Add(-time.Hour), now.Add(time.Hour)}
	past := [2]time.Time{now.Add(-2 * time.Hour), now.Add(-time.Second)}
	future := [2]time.Time{now.Add(notBeforeSkew + time.Second), now.Add(2 * time.Hour)}

	t.Run("both valid", func(t *testing.T) {
		leaf, ca := chain(t, valid[0], valid[1], valid[0], valid[1])
		if err := verifyDirectChain(leaf, ca, now); err != nil {
			t.Fatalf("verifyDirectChain = %v, want it accepted", err)
		}
	})

	t.Run("expired leaf", func(t *testing.T) {
		leaf, ca := chain(t, valid[0], valid[1], past[0], past[1])
		err := verifyDirectChain(leaf, ca, now)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("verifyDirectChain = %v, want an expiry rejection", err)
		}
		if strings.Contains(err.Error(), "mesh CA") {
			t.Fatalf("leaf expiry reported as a CA failure: %v", err)
		}
	})

	t.Run("expired CA", func(t *testing.T) {
		leaf, ca := chain(t, past[0], past[1], valid[0], valid[1])
		err := verifyDirectChain(leaf, ca, now)
		if err == nil || !strings.Contains(err.Error(), "committed mesh CA") {
			t.Fatalf("verifyDirectChain = %v, want the CA named in the rejection", err)
		}
	})

	t.Run("leaf not yet valid beyond the skew", func(t *testing.T) {
		leaf, ca := chain(t, valid[0], valid[1], future[0], future[1])
		err := verifyDirectChain(leaf, ca, now)
		if err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("verifyDirectChain = %v, want a not-yet-valid rejection", err)
		}
	})

	t.Run("leaf NotBefore inside the skew is accepted", func(t *testing.T) {
		leaf, ca := chain(t, valid[0], valid[1], now.Add(notBeforeSkew-time.Second), now.Add(time.Hour))
		if err := verifyDirectChain(leaf, ca, now); err != nil {
			t.Fatalf("verifyDirectChain = %v, want the skew allowance to accept a just-rotated leaf", err)
		}
	})
}
