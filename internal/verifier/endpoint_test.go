package verifier

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

//go:embed testdata/attestation.json
var azSnpFixture []byte

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

func TestEndpointAttesterRejectsUnsupportedPlatform(t *testing.T) {
	ea := newTestAttester(t, bundleHandler("commodore-64", "tls-cert", ""))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported platform") {
		t.Fatalf("want unsupported-platform error, got %v", err)
	}
}

func TestEndpointAttesterRejectsGarbageEvidence(t *testing.T) {
	// Correct binding + nonce, but the evidence payload is not a valid snp
	// envelope: verification (delegated to attestation-go) must fail closed.
	ea := newTestAttester(t, bundleHandler("snp", "tls-cert", ""))
	if _, err := ea.Attest(context.Background()); err == nil {
		t.Fatal("want verification failure for garbage snp evidence")
	}
}

// TestEndpointAttesterRejectsRecordedEvidence serves real az-snp evidence
// captured from an Azure CVM. The hardware report itself verifies (SNP
// signature + VCEK chain), but its vTPM quote is not bound to
// SHA-384(serving_leaf_spki || nonce) for this session, so the attester must
// fail closed rather than accept replayed evidence.
func TestEndpointAttesterRejectsRecordedEvidence(t *testing.T) {
	var envelope struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(azSnpFixture, &envelope); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	ea := newTestAttester(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  "c8s-verify/v1",
			"platform": envelope.Platform,
			"nonce":    r.URL.Query().Get("nonce"),
			"binding":  bindingTLSCert,
			"evidence": envelope.Evidence,
		})
	}))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "vTPM") {
		t.Fatalf("want vTPM freshness-binding failure for recorded evidence, got %v", err)
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

// Current c8s omits the binding field entirely: its attestation endpoint takes
// no binding parameter, so pq=false is the whole selection and there is nothing
// to echo. Requiring the echo made every such LB unverifiable, which is how
// this was found. The binding is established by the report_data check, not by
// the label, so an absent field must proceed to that check rather than fail.
func TestAttestAcceptsAbsentBinding(t *testing.T) {
	var envelope struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(azSnpFixture, &envelope); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	ea := newTestAttester(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  "c8s-verify/v1",
			"platform": envelope.Platform,
			"nonce":    r.URL.Query().Get("nonce"),
			// no "binding" key at all
			"evidence": envelope.Evidence,
		})
	}))
	_, err := ea.Attest(context.Background())
	if err == nil {
		t.Fatal("recorded evidence should still fail its freshness binding")
	}
	if strings.Contains(err.Error(), "binding") && strings.Contains(err.Error(), "pq=false") {
		t.Fatalf("absent binding rejected on the label instead of reaching the report_data check: %v", err)
	}
}

// A named binding that is not the one pq=false selects is still refused: that
// is an LB answering a different question from the one asked.
func TestAttestRejectsMismatchedBinding(t *testing.T) {
	var envelope struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(azSnpFixture, &envelope); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	ea := newTestAttester(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  "c8s-verify/v1",
			"platform": envelope.Platform,
			"nonce":    r.URL.Query().Get("nonce"),
			"binding":  "identity-pq",
			"evidence": envelope.Evidence,
		})
	}))
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "identity-pq") {
		t.Fatalf("want a refusal naming the selected binding, got %v", err)
	}
}
