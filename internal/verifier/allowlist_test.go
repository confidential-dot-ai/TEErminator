package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// servedDoc is a canonical-allowlist document whose byte string a JSON round
// trip does not preserve: the keys are not in the order encoding/json emits for
// a map, and the digest is over these exact bytes. Any re-encoding on the way
// from the socket to the caller changes them, and every test here compares
// against them byte-for-byte.
var servedDoc = []byte(`{"workloads":{"api":{"containers":[{"image":"ghcr.io/x/api@sha256:aa"}]}},"schema":"c8s.allowlist/v1"}`)

// serveAllowlist answers GET /allowlist the way c8s does: the document
// verbatim, application/json, and the weak ETag derived from the store version.
func serveAllowlist(raw []byte, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if version != "" {
			w.Header().Set("ETag", `W/"`+version+`"`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}
}

// attestAndFetch runs the whole capability against one fixture front door:
// attest, read the stamp off the chain-verified mesh leaf, fetch /allowlist
// from the same origin, check it against the stamp. The fetch client mirrors
// the proxy's construction — trust is the attestation, not the TLS PKI check.
func attestAndFetch(t *testing.T, f *lbFixture, spec bundleSpec) (*FetchedAllowlist, error) {
	t.Helper()
	ts := f.newServer(t, spec)
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	v, err := ea.Attest(context.Background())
	if err != nil {
		t.Fatalf("attestation failed before the fetch could run: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	return FetchAllowlist(context.Background(), client, ts.URL, v.Stamp)
}

// stampedFixture is a front door stamped for workload "api" at allowlistVersion
// over the exact bytes of stamped, serving served under servedVersion.
func stampedFixture(t *testing.T, stamped, served []byte, stampedVersion, servedVersion string) (*lbFixture, bundleSpec) {
	t.Helper()
	digest := sha256.Sum256(stamped)
	f := newLBFixture(t, fixtureOpts{
		allowlistRaw: stamped,
		stampExts:    []pkix.Extension{stampExt(t, "api", stampedVersion, digest[:])},
	})
	return f, bundleSpec{allowlist: serveAllowlist(served, servedVersion)}
}

func TestFetchAllowlistMatchingDocument(t *testing.T) {
	stubEvidence(t)
	f, spec := stampedFixture(t, servedDoc, servedDoc, "7", "7")

	doc, err := attestAndFetch(t, f, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Byte identity is the whole point: the digest is over what the socket
	// delivered, so anything that re-encoded the document on the way here
	// fails this comparison.
	if !bytes.Equal(doc.Raw, servedDoc) {
		t.Fatalf("fetched bytes were not returned verbatim:\n got %s\nwant %s", doc.Raw, servedDoc)
	}
	if want := sha256.Sum256(servedDoc); doc.Digest != want {
		t.Fatalf("digest = %x, want %x", doc.Digest, want)
	}
	if doc.Workload != "api" || doc.StampedVersion != "7" || doc.ServedVersion != "7" {
		t.Fatalf("doc = %q v%q (served v%q), want api v7 (served v7)", doc.Workload, doc.StampedVersion, doc.ServedVersion)
	}
	// The guard against a future re-encoding creeping in: the same document
	// through a JSON round trip is a different byte string, and would not have
	// matched the stamp.
	var round map[string]any
	if err := json.Unmarshal(doc.Raw, &round); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(round)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reencoded, servedDoc) {
		t.Fatal("fixture document survives a JSON round trip unchanged, so this test cannot detect a re-encoding; pick a document whose byte string encoding/json does not reproduce")
	}
}

func TestFetchAllowlistDigestMismatch(t *testing.T) {
	stubEvidence(t)
	// Same document with one byte appended: a different snapshot as far as the
	// digest is concerned.
	changed := append(append([]byte{}, servedDoc...), '\n')

	t.Run("served version newer: the cluster moved on", func(t *testing.T) {
		f, spec := stampedFixture(t, servedDoc, changed, "7", "9")
		_, err := attestAndFetch(t, f, spec)
		var mismatch *AllowlistDigestMismatch
		if !errors.As(err, &mismatch) {
			t.Fatalf("want an AllowlistDigestMismatch, got %v", err)
		}
		msg := err.Error()
		for _, want := range []string{
			"changed after this leaf was issued",
			"stamped version 7, served version 9",
			hex.EncodeToString(mismatch.StampedDigest),
			hex.EncodeToString(mismatch.ServedDigest[:]),
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("error %q does not mention %q", msg, want)
			}
		}
	})

	t.Run("served version equal: not churn", func(t *testing.T) {
		f, spec := stampedFixture(t, servedDoc, changed, "7", "7")
		_, err := attestAndFetch(t, f, spec)
		if err == nil || !strings.Contains(err.Error(), "SAME version as the stamp (7)") {
			t.Fatalf("want a substitution diagnosis, got %v", err)
		}
		if !strings.Contains(err.Error(), "do not use these bytes") {
			t.Errorf("error %q does not tell the operator what to do", err)
		}
	})

	t.Run("served version older: not churn either", func(t *testing.T) {
		f, spec := stampedFixture(t, servedDoc, changed, "10", "9")
		_, err := attestAndFetch(t, f, spec)
		if err == nil || !strings.Contains(err.Error(), "is OLDER than the stamped one") {
			t.Fatalf("want a rollback diagnosis, got %v", err)
		}
	})

	t.Run("no ETag: churn cannot be told apart", func(t *testing.T) {
		f, spec := stampedFixture(t, servedDoc, changed, "7", "")
		_, err := attestAndFetch(t, f, spec)
		if err == nil || !strings.Contains(err.Error(), "no usable version") {
			t.Fatalf("want an inconclusive diagnosis, got %v", err)
		}
	})
}

func TestFetchAllowlistStampedNameUnresolved(t *testing.T) {
	stubEvidence(t)
	// The stamp commits to exactly these bytes, but names a workload the
	// document does not contain: the digest matches and the fetch still fails.
	doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"web":{"containers":[]}}}`)
	f, spec := stampedFixture(t, doc, doc, "7", "7")

	got, err := attestAndFetch(t, f, spec)
	if err == nil || !strings.Contains(err.Error(), `stamped workload "api" does not resolve`) {
		t.Fatalf("want an unresolved-name failure, got (%v, %v)", got, err)
	}
	var mismatch *AllowlistDigestMismatch
	if errors.As(err, &mismatch) {
		t.Error("an unresolvable name is not a digest mismatch and must not be retried as one")
	}
}

func TestFetchAllowlistRejectsBadResponses(t *testing.T) {
	stubEvidence(t)
	digest := sha256.Sum256(servedDoc)

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			name:    "non-200",
			handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusForbidden) },
			want:    "returned 403",
		},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example/allowlist", http.StatusFound)
			},
			want: "returned 302",
		},
		{
			name: "not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write(servedDoc)
			},
			want: "unexpected content type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLBFixture(t, fixtureOpts{
				allowlistRaw: servedDoc,
				stampExts:    []pkix.Extension{stampExt(t, "api", "7", digest[:])},
			})
			_, err := attestAndFetch(t, f, bundleSpec{allowlist: tc.handler})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestFetchAllowlistWithoutStamp(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{noStamp: true})
	ts := f.newServer(t, bundleSpec{allowlist: serveAllowlist(servedDoc, "7")})
	ea := newLBAttester(t, ts, measuredRemote(), nil)

	v, err := ea.Attest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Stamp != nil {
		t.Fatalf("verdict carries a stamp %+v, want none for an unstamped leaf", v.Stamp)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := FetchAllowlist(context.Background(), client, ts.URL, v.Stamp); err == nil ||
		!strings.Contains(err.Error(), "no matched-workload stamp") {
		t.Fatalf("want a refusal to check a document against nothing, got %v", err)
	}
}

// TestAttestReadsStampWithoutPins covers the seam the fetch depends on: the
// stamp is read on every attestation, so `allowlist fetch` needs no pin — and a
// damaged stamp still fails the attestation closed, pin or no pin.
func TestAttestReadsStampWithoutPins(t *testing.T) {
	stubEvidence(t)

	t.Run("stamp is reported but not enforced", func(t *testing.T) {
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{})
		v, err := newLBAttester(t, ts, measuredRemote(), nil).Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.Stamp == nil || v.Stamp.Name != "api" || v.Stamp.AllowlistVersion != "7" {
			t.Fatalf("verdict stamp = %+v, want api v7", v.Stamp)
		}
		// Nothing was pinned, so nothing was checked: the enforced fields stay
		// empty even though the stamp was read.
		if v.WorkloadName != "" || v.AllowlistVersion != "" {
			t.Fatalf("unpinned verdict reports workload %q v%q as checked", v.WorkloadName, v.AllowlistVersion)
		}
	})

	t.Run("damaged stamp fails closed with no pin set", func(t *testing.T) {
		digest := sha256.Sum256(defaultAllowlistRaw)
		good := stampExt(t, "api", "7", digest[:])
		bad := pkix.Extension{Id: oidMatchedWorkload, Value: good.Value[:len(good.Value)-2]}
		f := newLBFixture(t, fixtureOpts{stampExts: []pkix.Extension{bad}})
		ts := f.newServer(t, bundleSpec{})
		_, err := newLBAttester(t, ts, measuredRemote(), nil).Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "workload policy") {
			t.Fatalf("want a damaged-stamp failure, got %v", err)
		}
	})
}

func TestVersionFromETag(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`W/"7"`, "7"},
		{` W/"12" `, "12"},
		{`"7"`, ""}, // strong ETag: not what c8s emits
		{"W/7", ""},
		{"", ""},
	} {
		if got := versionFromETag(tc.in); got != tc.want {
			t.Errorf("versionFromETag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCompareAllowlistVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		sign int
		ok   bool
	}{
		{"9", "7", 1, true},
		{"7", "7", 0, true},
		{"7", "10", -1, true}, // decimal, not lexical
		{"10", "9", 1, true},
		{"07", "7", 0, false}, // not the canonical encoding
		{"", "7", 0, false},
		{"x", "7", 0, false},
	} {
		got, ok := compareAllowlistVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && sign(got) != tc.sign) {
			t.Errorf("compareAllowlistVersions(%q, %q) = (%d, %v), want sign %d, ok %v", tc.a, tc.b, got, ok, tc.sign, tc.ok)
		}
	}
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}
