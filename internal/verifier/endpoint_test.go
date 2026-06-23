package verifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// bundleHandler serves a c8s-verify/v1 attestation bundle whose fields the test
// controls. It echoes the client nonce unless echoNonce overrides it.
func bundleHandler(platform, binding, echoNonce string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if echoNonce != "" {
			nonce = echoNonce
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  "c8s-verify/v1",
			"platform": platform,
			"nonce":    nonce,
			"binding":  binding,
			"evidence": json.RawMessage(`{"version":1,"hcl_report":"AA","vcek":"BB"}`),
		})
	}
}

func newTestAttester(t *testing.T, h http.Handler) *EndpointAttester {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	ea, err := NewEndpointAttester(ts.URL, ts.Client(), config.Remote{Mode: config.AttestEndpoint}, roots)
	if err != nil {
		t.Fatal(err)
	}
	return ea
}

func TestEndpointAttesterRequiresPinnedRoots(t *testing.T) {
	ea, err := NewEndpointAttester("https://lb.example", http.DefaultClient, config.Remote{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ea.Attest(context.Background()); err == nil || !strings.Contains(err.Error(), "mesh CA") {
		t.Fatalf("want pinned-mesh-CA error, got %v", err)
	}
}

func TestEndpointAttesterRejectsWrongBinding(t *testing.T) {
	// LB ignored pq=false and returned the over-encryption binding.
	ea := newTestAttester(t, bundleHandler("az-snp", "over-encryption", ""))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pq=false") {
		t.Fatalf("want pq=false binding error, got %v", err)
	}
}

func TestEndpointAttesterRejectsNonceMismatch(t *testing.T) {
	ea := newTestAttester(t, bundleHandler("az-snp", "tls-cert", "not-the-nonce"))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("want nonce mismatch error, got %v", err)
	}
}

func TestEndpointAttesterBareSNPUnsupported(t *testing.T) {
	// Correct binding + nonce, but bare-metal snp Flow B is not wired in Go yet.
	ea := newTestAttester(t, bundleHandler("snp", "tls-cert", ""))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bare-metal snp") {
		t.Fatalf("want bare-metal snp unsupported error, got %v", err)
	}
}

func TestEndpointAttesterNon200(t *testing.T) {
	ea := newTestAttester(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 error, got %v", err)
	}
}

func TestSessionCachePinning(t *testing.T) {
	c := NewSessionCache(time.Minute)
	if _, fresh, _ := c.FreshSession("r"); fresh {
		t.Fatal("empty cache should not be fresh")
	}
	want := [32]byte{1, 2, 3}
	c.RecordSession("r", true, want, nil)
	spki, fresh, ok := c.FreshSession("r")
	if !fresh || !ok || spki != want {
		t.Fatalf("FreshSession = (%x, %v, %v), want (%x, true, true)", spki, fresh, ok, want)
	}
	c.Invalidate("r")
	if _, fresh, _ := c.FreshSession("r"); fresh {
		t.Fatal("invalidated entry should not be fresh")
	}
}
