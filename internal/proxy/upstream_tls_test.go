package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// TestUpstreamTLSConfigMergesCertsAddRoots pins the acme-staging wiring.
// The attest paths (check.go, allowlist.go, proxy.go) hand
// upstreamTLSConfig's RootCAs to NewEndpointAttester as the WebPKI roots
// used by the acme serving-leaf check. A regression that stops merging
// `certs add` roots — or stops forwarding the pool — would silently break
// ACME staging and other private-CA front doors, because the verifier then
// sees only the system trust store. The verifier package separately proves
// that a supplied roots pool makes an acme door with a private CA verify
// (TestAttestLBAcmeFrontDoor); this test pins the proxy side of the chain.
func TestUpstreamTLSConfigMergesCertsAddRoots(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	extraCAs := []config.Cert{{CommonName: "staging-root", PEM: string(pemBytes)}}

	target, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with certs add, the added root verifies the serving leaf", func(t *testing.T) {
		cfg, err := upstreamTLSConfig(target, config.Remote{ServerName: "api.example.com"}, extraCAs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RootCAs == nil {
			t.Fatal("RootCAs is nil: certs add roots never reach the WebPKI check")
		}
		if cfg.ServerName != "api.example.com" {
			t.Fatalf("ServerName = %q, want the remote's override", cfg.ServerName)
		}
		// The pool built from the added root must verify the very certificate
		// it was built from: this is what verifyWebPKIChain does in acme mode.
		if _, err := ts.Certificate().Verify(x509.VerifyOptions{
			Roots:     cfg.RootCAs,
			DNSName:   "127.0.0.1",
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("serving leaf does not verify against the certs add pool: %v", err)
		}
	})

	t.Run("without certs add, RootCAs stays nil (system roots)", func(t *testing.T) {
		cfg, err := upstreamTLSConfig(target, config.Remote{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RootCAs != nil {
			t.Fatal("RootCAs is set without certs add entries; a nil pool selects the system store in verifyWebPKIChain")
		}
		if cfg.ServerName != target.Hostname() {
			t.Fatalf("ServerName = %q, want the URL host by default", cfg.ServerName)
		}
	})
}
