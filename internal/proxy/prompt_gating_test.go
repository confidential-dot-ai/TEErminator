package proxy

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// countingBody makes the sensitive request body observable without putting its
// bytes on the wire. An attest-lb failure must stop before RoundTrip consumes
// this reader, because the proxy has not yet decided that the upstream is
// trusted.
type countingBody struct {
	reads atomic.Int32
	data  *strings.Reader
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.data.Read(p)
}

func (b *countingBody) Close() error { return nil }

// TestAttestationFailureDoesNotReadPromptBody is the request-boundary
// regression: a failed attest-lb policy check must happen before the
// forwarding transport reads a prompt body or sends an HTTP request to the
// backend. The verifier package separately tests certificate, measurement,
// TCB, and workload mismatch errors; this test proves their common
// proxy gate does not release request bytes after any attestation error.
func TestAttestationFailureDoesNotReadPromptBody(t *testing.T) {
	var attestHits, promptHits atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/c8s/attest-lb" {
			attestHits.Add(1)
			// Deliberately return an invalid bundle. The endpoint attester must
			// fail closed before the request can be forwarded.
			http.Error(w, "not an attestation bundle", http.StatusBadGateway)
			return
		}
		promptHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "prompt reached backend")
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384([]byte("a1"))
	tr, err := newH3Transport(target, Options{
		Remote: config.Remote{Mode: config.AttestEndpoint, Measurements: []string{hex.EncodeToString(digest[:])}},
	})
	if err != nil {
		t.Fatalf("newH3Transport: %v", err)
	}
	defer func() { _ = tr.Close() }()

	body := &countingBody{data: strings.NewReader("sensitive prompt")}
	req, err := http.NewRequest(http.MethodPost, backend.URL+"/v1/chat", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("attestation failure returned a response")
	}
	if got := attestHits.Load(); got == 0 {
		t.Fatal("the test backend did not receive the attestation probe")
	}
	if got := promptHits.Load(); got != 0 {
		t.Fatalf("prompt reached backend %d time(s); want 0", got)
	}
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("prompt body was read %d time(s) after attestation failure; want 0", got)
	}
}

// A 429 must fail before inference. The next request must attempt a new check.
func TestAttestation429IsNotCached(t *testing.T) {
	var attestHits, promptHits atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/c8s/attest-lb" {
			attestHits.Add(1)
			http.Error(w, "caller limit", http.StatusTooManyRequests)
			return
		}
		promptHits.Add(1)
	}))
	defer backend.Close()
	digest := sha512.Sum384([]byte("a1"))
	tunnel, err := StartWithOptions(context.Background(), "127.0.0.1:0", backend.URL, Options{
		Remote:           config.Remote{Mode: config.AttestEndpoint, Measurements: []string{hex.EncodeToString(digest[:])}},
		ReattestInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for range 2 {
		resp, err := client.Post("http://"+tunnel.Addr()+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", resp.StatusCode)
		}
	}
	if got := attestHits.Load(); got != 2 {
		t.Fatalf("attestation checks = %d, want 2", got)
	}
	if got := promptHits.Load(); got != 0 {
		t.Fatalf("inference requests = %d, want 0", got)
	}
}
