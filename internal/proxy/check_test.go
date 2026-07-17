package proxy

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// caFor returns the test server's self-signed certificate as an ExtraCAs entry,
// so CheckRemote validates the server the way `certs add` would.
func caFor(t *testing.T, ts *httptest.Server) []config.Cert {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	return []config.Cert{{CommonName: "test-ca", PEM: string(pemBytes)}}
}

func TestCheckRemote(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	cas := caFor(t, backend)

	// A closed port: reserve one with a listener, then free it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "https://" + ln.Addr().String()
	_ = ln.Close()

	t.Run("no mode, reachable -> Untrusted", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: backend.URL}, cas)
		if res.Status != config.StatusUntrusted {
			t.Fatalf("status = %s (%s), want Untrusted", res.Status, res.Detail)
		}
	})

	t.Run("no mode, untrusted CA -> Failed", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: backend.URL}, nil)
		if res.Status != config.StatusFailed {
			t.Fatalf("status = %s, want Failed on TLS validation", res.Status)
		}
	})

	t.Run("no mode, unreachable -> Failed", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: deadURL}, cas)
		if res.Status != config.StatusFailed {
			t.Fatalf("status = %s, want Failed", res.Status)
		}
	})

	t.Run("attest, backend cannot attest -> Failed", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: backend.URL, Mode: config.AttestEndpoint}, cas)
		if res.Status != config.StatusFailed {
			t.Fatalf("status = %s, want Failed", res.Status)
		}
		if res.Detail == "" {
			t.Fatal("want a failure detail explaining the attestation error")
		}
	})

	t.Run("cds-cert (unimplemented) -> Failed", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: backend.URL, Mode: config.AttestCDSCert}, cas)
		if res.Status != config.StatusFailed || !strings.Contains(res.Detail, "not implemented") {
			t.Fatalf("status = %s (%s), want Failed with a not-implemented detail", res.Status, res.Detail)
		}
	})

	t.Run("invalid URL -> Failed", func(t *testing.T) {
		res := CheckRemote(ctx, config.Remote{Remote: "://bad"}, cas)
		if res.Status != config.StatusFailed {
			t.Fatalf("status = %s, want Failed", res.Status)
		}
	})
}
